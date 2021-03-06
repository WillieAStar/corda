package net.corda.node.services.vault

import co.paralleluniverse.fibers.Suspendable
import com.nhaarman.mockito_kotlin.*
import net.corda.core.contracts.*
import net.corda.core.flows.FinalityFlow
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.FlowSession
import net.corda.core.flows.InitiatingFlow
import net.corda.core.identity.AbstractParty
import net.corda.core.internal.FlowStateMachine
import net.corda.core.internal.packageName
import net.corda.core.internal.uncheckedCast
import net.corda.core.messaging.SingleMessageRecipient
import net.corda.core.node.StateLoader
import net.corda.core.node.services.KeyManagementService
import net.corda.core.node.services.queryBy
import net.corda.core.node.services.vault.QueryCriteria.SoftLockingCondition
import net.corda.core.node.services.vault.QueryCriteria.SoftLockingType.LOCKED_ONLY
import net.corda.core.node.services.vault.QueryCriteria.VaultQueryCriteria
import net.corda.core.transactions.LedgerTransaction
import net.corda.core.transactions.TransactionBuilder
import net.corda.core.utilities.NonEmptySet
import net.corda.core.utilities.OpaqueBytes
import net.corda.core.utilities.getOrThrow
import net.corda.core.utilities.unwrap
import net.corda.node.internal.InitiatedFlowFactory
import net.corda.node.services.api.VaultServiceInternal
import net.corda.node.services.config.NodeConfiguration
import net.corda.nodeapi.internal.ServiceInfo
import net.corda.testing.chooseIdentity
import net.corda.testing.node.MockNetwork
import net.corda.testing.rigorousMock
import org.junit.After
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.reflect.jvm.jvmName
import kotlin.test.assertEquals

private class NodePair(private val mockNet: MockNetwork) {
    private class ServerLogic(private val session: FlowSession, private val running: AtomicBoolean) : FlowLogic<Unit>() {
        @Suspendable
        override fun call() {
            running.set(true)
            session.receive<String>().unwrap { assertEquals("ping", it) }
            session.send("pong")
        }
    }

    @InitiatingFlow
    abstract class AbstractClientLogic<out T>(nodePair: NodePair) : FlowLogic<T>() {
        protected val server = nodePair.server.info.chooseIdentity()
        protected abstract fun callImpl(): T
        @Suspendable
        override fun call() = callImpl().also {
            initiateFlow(server).sendAndReceive<String>("ping").unwrap { assertEquals("pong", it) }
        }
    }

    private val serverRunning = AtomicBoolean()
    val server = mockNet.createNode()
    var client = mockNet.createNode().apply {
        internals.disableDBCloseOnStop() // Otherwise the in-memory database may disappear (taking the checkpoint with it) while we reboot the client.
    }
        private set

    fun <T> communicate(clientLogic: AbstractClientLogic<T>, rebootClient: Boolean): FlowStateMachine<T> {
        server.internals.internalRegisterFlowFactory(AbstractClientLogic::class.java, InitiatedFlowFactory.Core { ServerLogic(it, serverRunning) }, ServerLogic::class.java, false)
        client.services.startFlow(clientLogic)
        while (!serverRunning.get()) mockNet.runNetwork(1)
        if (rebootClient) {
            client.dispose()
            client = mockNet.createNode(client.internals.id)
        }
        return uncheckedCast(client.smm.allStateMachines.single().stateMachine)
    }
}

class VaultSoftLockManagerTest {
    private val mockVault = rigorousMock<VaultServiceInternal>().also {
        doNothing().whenever(it).softLockRelease(any(), anyOrNull())
    }
    private val mockNet = MockNetwork(cordappPackages = listOf(ContractImpl::class.packageName), defaultFactory = object : MockNetwork.Factory<MockNetwork.MockNode> {
        override fun create(config: NodeConfiguration, network: MockNetwork, networkMapAddr: SingleMessageRecipient?, id: Int, notaryIdentity: Pair<ServiceInfo, KeyPair>?, entropyRoot: BigInteger): MockNetwork.MockNode {
            return object : MockNetwork.MockNode(config, network, networkMapAddr, id, notaryIdentity, entropyRoot) {
                override fun makeVaultService(keyManagementService: KeyManagementService, stateLoader: StateLoader): VaultServiceInternal {
                    val realVault = super.makeVaultService(keyManagementService, stateLoader)
                    return object : VaultServiceInternal by realVault {
                        override fun softLockRelease(lockId: UUID, stateRefs: NonEmptySet<StateRef>?) {
                            mockVault.softLockRelease(lockId, stateRefs) // No need to also call the real one for these tests.
                        }
                    }
                }
            }
        }
    })
    private val nodePair = NodePair(mockNet)
    @After
    fun tearDown() {
        mockNet.stopNodes()
    }

    private object CommandDataImpl : CommandData
    private class ClientLogic(nodePair: NodePair, private val state: ContractState) : NodePair.AbstractClientLogic<List<ContractState>>(nodePair) {
        override fun callImpl() = run {
            subFlow(FinalityFlow(serviceHub.signInitialTransaction(TransactionBuilder(notary = ourIdentity).apply {
                addOutputState(state, ContractImpl::class.jvmName)
                addCommand(CommandDataImpl, ourIdentity.owningKey)
            })))
            serviceHub.vaultService.queryBy<ContractState>(VaultQueryCriteria(softLockingCondition = SoftLockingCondition(LOCKED_ONLY))).states.map {
                it.state.data
            }
        }
    }

    private abstract class SingleParticipantState(nodePair: NodePair) : ContractState {
        override val participants = listOf(nodePair.client.info.chooseIdentity())
    }

    private class PlainOldState(nodePair: NodePair) : SingleParticipantState(nodePair)
    private class FungibleAssetImpl(nodePair: NodePair) : SingleParticipantState(nodePair), FungibleAsset<Unit> {
        override val owner get() = participants[0]
        override fun withNewOwner(newOwner: AbstractParty) = throw UnsupportedOperationException()
        override val amount get() = Amount(1, Issued(PartyAndReference(owner, OpaqueBytes.of(1)), Unit))
        override val exitKeys get() = throw UnsupportedOperationException()
        override fun withNewOwnerAndAmount(newAmount: Amount<Issued<Unit>>, newOwner: AbstractParty) = throw UnsupportedOperationException()
        override fun equals(other: Any?) = other is FungibleAssetImpl && participants == other.participants
        override fun hashCode() = participants.hashCode()
    }

    class ContractImpl : Contract {
        override fun verify(tx: LedgerTransaction) {}
    }

    private fun run(expectSoftLock: Boolean, state: ContractState, checkpoint: Boolean) {
        val fsm = nodePair.communicate(ClientLogic(nodePair, state), checkpoint)
        mockNet.runNetwork()
        if (expectSoftLock) {
            assertEquals(listOf(state), fsm.resultFuture.getOrThrow())
            verify(mockVault).softLockRelease(fsm.id.uuid, null)
        } else {
            assertEquals(emptyList(), fsm.resultFuture.getOrThrow())
            // In this case we don't want softLockRelease called so that we avoid its expensive query, even after restore from checkpoint.
        }
        verifyNoMoreInteractions(mockVault)
    }

    @Test
    fun `plain old state is not soft locked`() = run(false, PlainOldState(nodePair), false)

    @Test
    fun `plain old state is not soft locked with checkpoint`() = run(false, PlainOldState(nodePair), true)

    @Test
    fun `fungible asset is soft locked`() = run(true, FungibleAssetImpl(nodePair), false)

    @Test
    fun `fungible asset is soft locked with checkpoint`() = run(true, FungibleAssetImpl(nodePair), true)
}
