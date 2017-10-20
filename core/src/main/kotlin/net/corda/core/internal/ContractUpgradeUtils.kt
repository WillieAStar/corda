package net.corda.core.internal

import net.corda.core.contracts.*
import net.corda.core.node.ServiceHub
import net.corda.core.transactions.ContractUpgradeWireTransaction

object ContractUpgradeUtils {
    fun <OldState : ContractState, NewState : ContractState> assembleUpgradeTx(
            stateAndRef: StateAndRef<OldState>,
            upgradedContractClass: Class<out UpgradedContract<OldState, NewState>>,
            privacySalt: PrivacySalt,
            services: ServiceHub
    ): ContractUpgradeWireTransaction {
        val legacyContractConstraint = services.cordappProvider.getContractAttachmentID(stateAndRef.state.contract)?.let { HashAttachmentConstraint(it) }!!
        val upgradedContractConstraint = services.cordappProvider.getContractAttachmentID(upgradedContractClass.name)?.let { HashAttachmentConstraint(it) }!!

        val contractUpgrade = upgradedContractClass.newInstance()
        val inputs = listOf(stateAndRef.ref)
        val outputs = listOf(stateAndRef.state).map {
            val oldState = it.data
            val newState = contractUpgrade.upgrade(oldState)
            // TODO: copy across encumbrances
            TransactionState(newState, upgradedContractClass.name, it.notary, it.encumbrance, upgradedContractConstraint)
        }

        return ContractUpgradeWireTransaction(inputs, outputs, stateAndRef.state.notary, legacyContractConstraint.attachmentId, upgradedContractConstraint.attachmentId, privacySalt)
    }
}
