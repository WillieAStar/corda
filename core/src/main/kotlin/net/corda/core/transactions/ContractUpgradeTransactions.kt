package net.corda.core.transactions

import net.corda.core.contracts.*
import net.corda.core.crypto.SecureHash
import net.corda.core.crypto.TransactionSignature
import net.corda.core.crypto.serializedHash
import net.corda.core.identity.Party
import net.corda.core.node.ServiceHub
import net.corda.core.serialization.CordaSerializable
import net.corda.core.utilities.Try
import net.corda.core.utilities.toBase58String
import java.security.PublicKey

// TODO: copy across encumbrances when performing contract upgrades

/** A special transaction for upgrading the contract of a state. */
@CordaSerializable
data class ContractUpgradeWireTransaction(
        override val inputs: List<StateRef>,
        override val outputs: List<TransactionState<ContractState>>,
        override val notary: Party,
        val legacyContractAttachment: SecureHash,
        val upgradedContractAttachment: SecureHash,
        val privacySalt: PrivacySalt = PrivacySalt()
) : CoreTransaction() {

    init {
        check(inputs.isNotEmpty()) { "A contract upgrade transaction must have inputs" }
        check(inputs.size == outputs.size) { "A contract upgrade transaction must have a corresponding output for every input" }
    }

    /** Hash of the component list that are hidden in the [ContractUpgradeFilteredTransaction]. */
    private val hiddenComponentHash: SecureHash get() = serializedHash(outputs + legacyContractAttachment + upgradedContractAttachment)

    override val id: SecureHash by lazy { serializedHash(inputs + notary + hiddenComponentHash) }

    fun resolve(services: ServiceHub, sigs: List<TransactionSignature>): ContractUpgradeLedgerTransaction {
        val resolvedInputs = inputs.map { ref ->
            services.loadState(ref).let { StateAndRef(it, ref) }
        }
        val legacyContract = services.attachments.openAttachment(legacyContractAttachment)!!
        val upgradedContract = services.attachments.openAttachment(upgradedContractAttachment)!!
        return ContractUpgradeLedgerTransaction(resolvedInputs, outputs, notary, legacyContract, upgradedContract, id, privacySalt, sigs)
    }

    fun buildFilteredTransaction(): ContractUpgradeFilteredTransaction {
        return ContractUpgradeFilteredTransaction(inputs, notary, hiddenComponentHash)
    }
}
/**
 * A filtered version of the [ContractUpgradeWireTransaction]. In comparison with a regular [FilteredTransaction], there
 * is no flexibility on what parts of the transaction to reveal – the inputs and notary field are always visible and the
 * rest of the transaction is always hidden. Its only purpose is to hide transaction data when using a non-validating notary.
 */
@CordaSerializable
data class ContractUpgradeFilteredTransaction(
        val inputs: List<StateRef>,
        val notary: Party,
        val rest: SecureHash
) : NamedByHash {
    override val id: SecureHash get() = serializedHash(inputs + notary + rest)
}

/**
 * A contract upgrade transaction with fully resolved inputs and signatures. In contrast with a regular transaction,
 * signatures are checked against the signers specified by input states' *participants* fields, so full resolution is
 * needed for signature verification.
 */
data class ContractUpgradeLedgerTransaction(
        override val inputs: List<StateAndRef<ContractState>>,
        override val outputs: List<TransactionState<ContractState>>,
        override val notary: Party,
        val legacyContractAttachment: Attachment,
        val upgradedContractAttachment: Attachment,
        override val id: SecureHash,
        val privacySalt: PrivacySalt,
        override val sigs: List<TransactionSignature>
) : FullTransaction(), TransactionWithSignatures {

    private val legacyContractName: ContractClassName = inputs.first().state.contract
    private val legacyContractConstraint: AttachmentConstraint = inputs.first().state.constraint
    private val upgradedContractName: ContractClassName = outputs.first().contract
    private val upgradedContractTry: Try<UpgradedContract<ContractState, *>> = Try.on {
        @Suppress("UNCHECKED_CAST")
        this::class.java.classLoader.loadClass(upgradedContractName).asSubclass(Contract::class.java).getConstructor().newInstance() as UpgradedContract<ContractState, *>
    }

    init {
        check(inputs.all { it.state.contract == legacyContractName }) { "All input states point to the legacy contract" }
        check(outputs.all { it.contract == upgradedContractName }) { "All output states point to the upgraded contract" }
    }

    /** We compute the outputs lazily by applying the contract upgrade field modification to the inputs */
    override val requiredSigningKeys: Set<PublicKey>
        get() = inputs.flatMap { it.state.data.participants }.map { it.owningKey }.toSet() + notary.owningKey

    override fun getKeyDescriptions(keys: Set<PublicKey>): List<String> {
        return keys.map { it.toBase58String() }
    }

    override fun verify() {
        val upgradedContract = when (upgradedContractTry) {
            is Try.Failure -> throw TransactionVerificationException.ContractCreationError(id, upgradedContractName, upgradedContractTry.exception)
            is Try.Success -> upgradedContractTry.value
        }

        check(upgradedContract.legacyContract == legacyContractName &&
                upgradedContract.legacyContractConstraint == legacyContractConstraint) {
            "Outputs' contract must be an upgraded version of the inputs' contract"
        }

        inputs.forEachIndexed { index, stateAndRef ->
            val legacyState = stateAndRef.state.data
            val upgradedState = outputs[index].data
            val expectedUpgradedState = upgradedContract.upgrade(legacyState)
            check(upgradedState == expectedUpgradedState) {
                "Output at index $index is not an upgraded version of the corresponding input"
            }
        }
    }
}