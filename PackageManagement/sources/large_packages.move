/// # Aptos Large Packages Framework
///
/// This module provides a framework for uploading large packages to the Aptos network, under standard
/// accounts or objects.
/// To publish using this API, you must divide your metadata and modules across multiple calls
/// into `large_packages::stage_code_chunk`.
/// In each pass, the caller pushes more code by calling `stage_code_chunk`.
/// In the final call, the caller can use `stage_code_chunk_and_publish_to_account`, `stage_code_chunk_and_publish_to_object`, or
/// `stage_code_chunk_and_upgrade_object_code` to upload the final data chunk and publish or upgrade the package on-chain.
///
/// The above logic is currently implemented in the Python
/// SDK: [`aptos-python-sdk`](https://github.com/aptos-labs/aptos-python-sdk/blob/main/aptos_sdk/package_publisher.py).
///
/// Aptos CLI supports this as well with `--chunked-publish` flag:
/// - `aptos move publish [OPTIONS] --chunked-publish`
/// - `aptos move create-object-and-publish-package [OPTIONS] --address-name <ADDRESS_NAME> --chunked-publish`
/// - `aptos move upgrade-object-package [OPTIONS] --address-name <ADDRESS_NAME> --chunked-publish`
///
/// # Usage
///
/// 1. **Stage Code Chunks**:
///     - Call `stage_code_chunk` with the appropriate metadata and code chunks.
///     - Ensure that `code_indices` are provided from `0` to `last_module_idx`, without any
///       gaps.
///
///
/// 2. **Publish or Upgrade**:
///     - In order to upload the last data chunk and publish the package, call `stage_code_chunk_and_publish_to_account` or `stage_code_chunk_and_publish_to_object`.
///
///     - For object code upgrades, call `stage_code_chunk_and_upgrade_object_code` with the argument `code_object` provided.
///
/// 3. **Cleanup**:
///     - In order to remove `StagingArea` resource from an account, call `cleanup_staging_area`.
///
/// # Notes
///
/// * Make sure LargePackages is deployed to your network of choice, you can currently find it both on
///   mainnet and testnet at `0xa29df848eebfe5d981f708c2a5b06d31af2be53bbd8ddc94c8523f4b903f7adb`, and
///   in 0x7 (aptos-experimental) on devnet/localnet.
/// * Ensure that `code_indices` have no gaps. For example, if code_indices are
///   provided as [0, 1, 3] (skipping index 2), the inline function `assemble_module_code` will abort
///   since `StagingArea.last_module_idx` is set as the max value of the provided index
///   from `code_indices`, and `assemble_module_code` will lookup the `StagingArea.code` SmartTable from
///   0 to `StagingArea.last_module_idx` in turn.
module package_management::large_packages {
    use std::error;
    use std::option::Option;
    use std::signer;
    use std::vector;
    use aptos_std::aptos_hash::sha3_512;
    use aptos_std::big_ordered_map::{Self, BigOrderedMap};
    use aptos_std::ordered_map::{Self, OrderedMap};
    use aptos_framework::code;
    use aptos_framework::object;

    /// code_indices and code_chunks should be the same length.
    const E_CODE_LENGTH_MISMATCH: u64 = 1;
    /// Object reference should be provided when upgrading object code.
    const EMISSING_OBJECT_REFERENCE: u64 = 2;
    /// Please close or publish existing proposals before creating new ones.
    const ETOO_MANY_OPEN_PROPOSALS: u64 = 3;

    /// Destination address doesn't match the expected address
    const E_ADDRESS_MISMATCH: u64 = 4;

    /// Code hash doesn't match the expected hash
    const E_HASH_MISMATCH: u64 = 5;

    /// No staging info found for the chunker, which means the chunker has not staged any proposals before.
    const E_NO_STAGING_INFO: u64 = 6;

    /// No proposal found for the given proposal ID.
    const E_NO_PROPOSAL: u64 = 7;

    /// Maximum number of open proposals allowed per chunker to prevent spamming.
    const MAX_OPEN_PROPOSALS: u64 = 5;

    /// Resource that holds the staging information for a chunker, including the next staging ID and the mapping from
    /// staging IDs to proposal addresses. This resource is stored under the chunker's account.
    enum StagingInfo has key {
        V1 {
            /// The next staging ID to be used for a new proposal. This is incremented every time a new proposal is
            /// staged, and is used to generate unique addresses for proposal objects.
            staging_id: u64,
            /// The mapping from proposal IDs to proposal object addresses. When a new proposal is staged, its ID and
            /// address are added to this map, and when a proposal is removed or published, its entry is removed from
            /// this map.
            proposals: OrderedMap<u64, address>
        }
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    /// Resource that represents a proposal for a large package deployment. This resource is stored as an object, and
    /// its address is generated based on the chunker's address and the proposal ID.
    enum Proposal has key {
        V1 {
            /// The destination address for the deployment. This can be either a standard account or an object, but it
            /// must be the same across all stages of the proposal.
            destination: address,
            /// The metadata of the package, which can be uploaded in chunks. The final metadata will be assembled by
            /// concatenating the metadata chunks in the order of their arrival.
            metadata: vector<u8>,
            /// The code modules of the package, which can be uploaded in chunks. This is used for verification on upload.
            num_modules: u16,
            /// The code modules of the package, which can be uploaded in chunks. The final code will be assembled by
            /// concatenating the code chunks in the order of their indices, so they should be pushed in the correct order.
            code_modules: BigOrderedMap<u16, vector<u8>>,
            /// The delete ref for the proposal object, which will be used to delete the object when the proposal is
            /// removed or published.
            delete_ref: object::DeleteRef
        }
    }

    /// Stages a new deployment by creating a proposal object and enqueuing it.
    ///
    /// Limited to MAX_OPEN_PROPOSALS active proposals at a time to prevent spamming. The proposal object will be
    /// created with the chunker's address as the owner, and the proposal's address will be stored in StagingInfo for
    /// the chunker.
    public entry fun stage_new_deployment(
        chunker: &signer, destination: address, num_modules: u16
    ) {
        enqueue_proposal(
            chunker,
            |_staging_id| {
                let proposal_const_ref =
                    object::create_object(signer::address_of(chunker));
                let delete_ref = proposal_const_ref.generate_delete_ref();

                // Disable transfer
                {
                    proposal_const_ref.generate_transfer_ref().disable_ungated_transfer()
                };

                let proposal = Proposal::V1 {
                    destination,
                    num_modules,
                    metadata: vector[],
                    // `vector<u8>` has variable BCS size; use `new_with_config` instead of `new`.
                    code_modules: big_ordered_map::new_with_config<u16, vector<u8>>(
                        0, 0, false
                    ),
                    delete_ref
                };
                move_to(&proposal_const_ref.generate_signer(), proposal);
                proposal_const_ref.address_from_constructor_ref()
            }
        );
    }

    /// Removes a proposal by its ID. This will delete the proposal object and remove its reference from StagingInfo.
    entry fun remove_proposal(chunker: &signer, proposal_id: u64) {
        let info = staging_info_mut(chunker);
        assert!(info.proposals.contains(&proposal_id), error::not_found(E_NO_PROPOSAL));

        // Remove the proposal from StagingInfo and delete the proposal object
        let proposal_addr = info.proposals.remove(&proposal_id);
        let proposal = move_from<Proposal>(proposal_addr);

        // Delete the object
        proposal.destroy_proposal();
    }

    /// Clears all proposals for the chunker. This is a helper function that can be used to clean up all proposals in case of any issues.
    entry fun clear_proposals(chunker: &signer) {
        let info = staging_info_mut(chunker);
        let proposal_ids = info.proposals.keys();

        proposal_ids.for_each(
            |proposal_id| {
                let proposal_address = info.proposals.remove(&proposal_id);
                let proposal = move_from<Proposal>(proposal_address);
                proposal.destroy_proposal();
            }
        );
    }

    /// Add a metadata chunk to the proposal. Metadata chunks will be concatenated in the order of their arrival, so
    /// they should be pushed in the correct order.
    public entry fun stage_metadata(
        chunker: &signer, proposal_id: u64, metadata_chunk: vector<u8>
    ) {
        let proposal_addr =
            proposal_object_address(signer::address_of(chunker), proposal_id);
        let proposal = &mut Proposal[proposal_addr];
        proposal.metadata.append(metadata_chunk);
    }

    /// Concatenate two owned `vector<u8>` values (avoids `borrow_mut` on `BigOrderedMap` with variable-sized values).
    fun merge_u8_chunks(prior: vector<u8>, more: vector<u8>): vector<u8> {
        vector::append(&mut prior, more);
        prior
    }

    /// Stages a code chunk to the proposal. Code chunks will be merged based on their provided index, so the same index
    /// can be pushed multiple times and the chunks will be concatenated in the order of their arrival. The final code
    /// will be assembled by concatenating the code chunks in the order of their indices, so they should be pushed in
    /// the correct order.
    entry fun stage_code_chunk(
        chunker: &signer,
        proposal_id: u64,
        code_indices: vector<u16>,
        code_chunks: vector<vector<u8>>
    ) {
        assert!(
            code_indices.length() == code_chunks.length(),
            error::invalid_argument(E_CODE_LENGTH_MISMATCH)
        );
        let proposal_addr =
            proposal_object_address(signer::address_of(chunker), proposal_id);
        let proposal = &mut Proposal[proposal_addr];
        for (i in 0..code_chunks.length()) {
            // Merge existing data (`borrow_mut` is not valid for variable-size `vector<u8>` values).
            if (proposal.code_modules.contains(&code_indices[i])) {
                let merged = proposal.code_modules.remove(&code_indices[i]);
                proposal.code_modules.add(
                    code_indices[i],
                    merge_u8_chunks(merged, code_chunks[i])
                );
            } else {
                proposal.code_modules.add(code_indices[i], code_chunks[i]);
            }
        };
    }

    /// Publishes the staged package to the destination account. This will assemble the code chunks, verify the data hash, publish the package, and clean up the proposal.
    entry fun publish_proposal_to_account(
        publisher: &signer,
        chunker: address,
        proposal_id: u64,
        expected_hash: Option<vector<u8>>
    ) {
        publish_proposal_to_item(
            signer::address_of(publisher),
            chunker,
            proposal_id,
            expected_hash,
            |metadata, code| {
                code::publish_package_txn(publisher, metadata, code);
            }
        );
    }

    // TODO: support code objects

    // TODO: add view functions to get the staging status, such as the number of chunks staged, the total size of staged data, etc.

    /// Publishes the staged package to the destination object. This will assemble the code chunks,
    /// verify the data hash, publish the package, and clean up the proposal.
    inline fun publish_proposal_to_item(
        destination: address,
        chunker: address,
        proposal_id: u64,
        expected_hash: Option<vector<u8>>,
        publish: |vector<u8>, vector<vector<u8>>|
    ) {
        let proposal_addr = proposal_object_address(chunker, proposal_id);
        let (code, metadata) = {
            // Check that the proposal has the right destination
            let proposal = &mut Proposal[proposal_addr];
            assert!(
                proposal.destination == destination,
                error::invalid_argument(E_ADDRESS_MISMATCH)
            );

            // Check that the code length matches the expected number of modules
            let code = proposal.assemble_module_code();
            assert!(
                code.length() == (proposal.num_modules as u64),
                error::invalid_argument(E_CODE_LENGTH_MISMATCH)
            );

            // Check the code hash if provided
            if (expected_hash.is_some()) {
                let hashable = proposal.metadata;
                code.for_each_ref(|chunk| hashable.append(*chunk));
                let hash = sha3_512(hashable);
                assert!(&hash == expected_hash.borrow(), error::aborted(E_HASH_MISMATCH));
            };

            (code, proposal.metadata)
        };

        // Validation and building is done, so publish it
        publish(metadata, code);

        // Clean up proposal after successful publish
        let proposal = move_from<Proposal>(proposal_addr);

        // Delete the object
        proposal.destroy_proposal();
    }

    /// Enqueues a new proposal for the chunker.
    inline fun enqueue_proposal(
        chunker: &signer, proposal_obj: |u64| address
    ) {
        let chunker_address = signer::address_of(chunker);
        if (!exists<StagingInfo>(chunker_address)) {
            let staging_info = StagingInfo::V1 { proposals: ordered_map::new(), staging_id:
                0 };
            move_to(chunker, staging_info);
        };

        // Only allow MAX_OPEN_PROPOSALS active proposals to prevent too much
        let info = staging_info_mut(chunker);
        assert!(info.proposals.length() < MAX_OPEN_PROPOSALS, ETOO_MANY_OPEN_PROPOSALS);
        let current_id = info.staging_id;
        let obj_addr = proposal_obj(current_id);
        info.staging_id = current_id + 1;
        info.proposals.add(current_id, obj_addr);
    }

    /// Destroys the proposal by deleting the proposal object. This is a helper function that can be used to clean
    /// up a proposal in case of any issues.
    inline fun destroy_proposal(self: Proposal) {
        match(self) {
            Proposal::V1 { delete_ref, code_modules,.. } => {
                delete_ref.delete();
                code_modules.destroy(|_| {});
            }
        };
    }

    /// Returns the on-chain address of the proposal object for this chunker and proposal ID (from `StagingInfo`).
    inline fun proposal_object_address(chunker: address, proposal_id: u64): address {
        let info = staging_info_ref(chunker);
        assert!(info.proposals.contains(&proposal_id), error::not_found(E_NO_PROPOSAL));
        *info.proposals.borrow(&proposal_id)
    }

    /// Assembles the code by concatenating the code chunks in the order of their indices.
    inline fun assemble_module_code(self: &mut Proposal): vector<vector<u8>> {
        let code = vector[];
        self.code_modules.for_each_and_clear(
            |_, code_module| { code.push_back(code_module) }
        );
        code
    }

    inline fun staging_info_mut(chunker: &signer): &mut StagingInfo {
        let chunker_address = signer::address_of(chunker);
        assert!(
            exists<StagingInfo>(chunker_address),
            error::not_found(E_NO_STAGING_INFO)
        );
        &mut StagingInfo[chunker_address]
    }

    inline fun staging_info_ref(chunker_address: address): &StagingInfo {
        assert!(
            exists<StagingInfo>(chunker_address),
            error::not_found(E_NO_STAGING_INFO)
        );
        &StagingInfo[chunker_address]
    }

    // -- Unit tests (same module so private `entry` functions can be exercised) ----
    #[test_only]
    use aptos_framework::account;

    #[test_only]
    use std::features;

    #[test_only]
    use std::option;

    #[test(chunker = @0xC0FFEE, publisher = @0xBEEF)]
    fun test_stage_metadata_and_code_then_remove(
        chunker: &signer, publisher: &signer
    ) {
        account::create_account_for_test(signer::address_of(chunker));
        account::create_account_for_test(signer::address_of(publisher));
        stage_new_deployment(chunker, signer::address_of(publisher), 1);
        stage_metadata(chunker, 0, b"meta");
        stage_code_chunk(chunker, 0, vector[0u16], vector[b"m1"]);
        stage_code_chunk(chunker, 0, vector[0u16], vector[b"m2"]);
        remove_proposal(chunker, 0);
    }

    #[test(chunker = @0xCAFE)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_stage_code_chunk_length_mismatch_aborts(chunker: &signer) {
        account::create_account_for_test(signer::address_of(chunker));
        stage_new_deployment(chunker, @0xB0B0, 1);
        stage_code_chunk(chunker, 0, vector[0u16, 1u16], vector[b"a"]);
    }

    #[test(chunker = @0xD00D)]
    #[expected_failure(abort_code = 0x60006, location = Self)]
    fun test_remove_proposal_without_staging_info_aborts(
        chunker: &signer
    ) {
        account::create_account_for_test(signer::address_of(chunker));
        remove_proposal(chunker, 0);
    }

    #[test(chunker = @0xE111)]
    #[expected_failure(abort_code = 0x60007, location = Self)]
    fun test_remove_missing_proposal_aborts(chunker: &signer) {
        account::create_account_for_test(signer::address_of(chunker));
        stage_new_deployment(chunker, @0xABBA, 1);
        remove_proposal(chunker, 99);
    }

    #[test(chunker = @0xF500, publisher = @0xBEEF)]
    #[expected_failure(abort_code = 3, location = Self)]
    fun test_sixth_staged_proposal_exceeds_limit(
        chunker: &signer, publisher: &signer
    ) {
        account::create_account_for_test(signer::address_of(chunker));
        account::create_account_for_test(signer::address_of(publisher));
        let dest = signer::address_of(publisher);
        let i = 0;
        while (i < MAX_OPEN_PROPOSALS) {
            stage_new_deployment(chunker, dest, 1);
            i = i + 1;
        };
        stage_new_deployment(chunker, dest, 1);
    }

    #[test(chunker = @0xC1, publisher = @0xB1, attacker = @0xA1)]
    #[expected_failure(abort_code = 0x10004, location = Self)]
    fun test_publish_proposal_wrong_publisher_address_aborts(
        chunker: &signer, publisher: &signer, attacker: &signer
    ) {
        account::create_account_for_test(signer::address_of(chunker));
        account::create_account_for_test(signer::address_of(publisher));
        account::create_account_for_test(signer::address_of(attacker));
        stage_new_deployment(chunker, signer::address_of(publisher), 1);
        stage_code_chunk(chunker, 0, vector[0u16], vector[b"code"]);
        publish_proposal_to_account(
            attacker,
            signer::address_of(chunker),
            0,
            option::none()
        );
    }

    #[test(chunker = @0xC2, publisher = @0xB2)]
    #[expected_failure(abort_code = 0x10001, location = Self)]
    fun test_publish_proposal_module_count_mismatch_aborts(
        chunker: &signer, publisher: &signer
    ) {
        account::create_account_for_test(signer::address_of(chunker));
        account::create_account_for_test(signer::address_of(publisher));
        stage_new_deployment(chunker, signer::address_of(publisher), 2);
        stage_code_chunk(chunker, 0, vector[0u16], vector[b"only-one"]);
        publish_proposal_to_account(
            publisher,
            signer::address_of(chunker),
            0,
            option::none()
        );
    }

    #[test(fx = @aptos_std, chunker = @0xC3, publisher = @0xB3)]
    #[expected_failure(abort_code = 0x70005, location = Self)]
    fun test_publish_proposal_hash_mismatch_aborts(
        fx: &signer, chunker: &signer, publisher: &signer
    ) {
        features::change_feature_flags_for_testing(
            fx,
            vector[features::get_sha_512_and_ripemd_160_feature()],
            vector[]
        );
        account::create_account_for_test(signer::address_of(chunker));
        account::create_account_for_test(signer::address_of(publisher));
        stage_new_deployment(chunker, signer::address_of(publisher), 1);
        stage_code_chunk(chunker, 0, vector[0u16], vector[b"code"]);
        publish_proposal_to_account(
            publisher,
            signer::address_of(chunker),
            0,
            option::some(
                x"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            )
        );
    }

    #[test(chunker = @0xC4, publisher = @0xB4)]
    fun test_clear_proposals_removes_open_proposals(
        chunker: &signer, publisher: &signer
    ) {
        account::create_account_for_test(signer::address_of(chunker));
        account::create_account_for_test(signer::address_of(publisher));
        stage_new_deployment(chunker, signer::address_of(publisher), 1);
        clear_proposals(chunker);
    }
}
