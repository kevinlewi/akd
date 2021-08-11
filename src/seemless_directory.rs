// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
use crate::append_only_zks::{AppendOnlyProof, NonMembershipProof};
use crate::append_only_zks::{Azks, MembershipProof};
use crate::errors::{SeemlessDirectoryError, SeemlessError};
use crate::node_state::{HistoryNodeState, NodeLabel};
use crate::storage::Storage;
use crypto::Hasher;
use rand::{prelude::ThreadRng, thread_rng};
use std::collections::HashMap;
use std::marker::PhantomData;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Username(String);

// impl PartialEq for Username {
//     fn eq(&self, other: &Self) -> bool {
//         self.0 == other.0
//     }
// }

// impl Eq for Username {}

#[derive(Clone)]
pub struct Values(String);

#[derive(Clone)]
pub struct UserState {
    plaintext_val: Values, // This needs to be the plaintext value, to discuss
    version: u64,          // to discuss
    label: NodeLabel,
    epoch: u64,
}

impl UserState {
    pub fn new(plaintext_val: Values, version: u64, label: NodeLabel, epoch: u64) -> Self {
        UserState {
            plaintext_val,
            version,
            label,
            epoch,
        }
    }
}

#[derive(Clone)]
pub struct UserData {
    states: Vec<UserState>,
}

impl UserData {
    pub fn new(state: UserState) -> Self {
        UserData {
            states: vec![state],
        }
    }
}

pub struct LookupProof<H: Hasher> {
    epoch: u64,
    plaintext_value: Values,
    version: u64,
    existence_proof: MembershipProof<H>,
    marker_proof: MembershipProof<H>,
    freshness_proof: NonMembershipProof<H>,
}

pub struct UpdateProof<H: Hasher> {
    epoch: u64,
    plaintext_value: Values,
    version: u64,
    existence_at_ep: MembershipProof<H>, // membership proof to show that the key was included in this epoch
    previous_val_stale_at_ep: MembershipProof<H>, // proof that previous value was set to old at this epoch
    non_existence_before_ep: NonMembershipProof<H>, // proof that this value didn't exist prior to this ep
    non_existence_of_next_few: Vec<NonMembershipProof<H>>, // proof that the next few values did not exist at this time
    non_existence_of_future_markers: Vec<NonMembershipProof<H>>, // proof that future markers did not exist
}

pub struct HistoryProof<H: Hasher> {
    proofs: Vec<UpdateProof<H>>,
}

pub struct SeemlessDirectory<S: Storage<HistoryNodeState<H>>, H: Hasher> {
    azks: Azks<H, S>,
    user_data: HashMap<Username, UserData>,
    current_epoch: u64,
    _s: PhantomData<S>,
    _h: PhantomData<H>,
}

impl<S: Storage<HistoryNodeState<H>>, H: Hasher> SeemlessDirectory<S, H> {
    pub fn new() -> Self {
        let mut rng: ThreadRng = thread_rng();
        SeemlessDirectory {
            azks: Azks::<H, S>::new(&mut rng),
            user_data: HashMap::<Username, UserData>::new(),
            current_epoch: 0,
            _s: PhantomData::<S>,
            _h: PhantomData::<H>,
        }
    }

    // FIXME: this code won't work
    pub fn publish(&mut self, updates: Vec<(Username, Values)>) -> Result<(), SeemlessError> {
        // for (_key, _val) in updates {
        //     S::set("0".to_string(), HistoryNodeState::new())
        //         .map_err(|_| SeemlessDirectoryError::StorageError)?;
        // }
        let mut update_set = Vec::<(NodeLabel, H::Digest)>::new();
        let mut user_data_update_set = Vec::<(Username, UserData)>::new();
        let next_epoch = self.current_epoch + 1;
        for update in updates {
            let (uname, val) = update;
            let data = &self.user_data.get(&uname);
            match data {
                None => {
                    let latest_version = 1;
                    let label = Self::get_nodelabel(&uname, false, latest_version);
                    // Currently there's no blinding factor for the commitment.
                    // We'd want to change this later.
                    let value_to_add = H::hash(&Self::value_to_bytes(&val));
                    update_set.push((label, value_to_add));
                    let latest_state = UserState::new(val, latest_version, label, next_epoch);
                    user_data_update_set.push((uname, UserData::new(latest_state)));
                }
                Some(user_data_val) => {
                    let latest_st = user_data_val.states.last().unwrap();
                    let previous_version = latest_st.version;
                    let latest_version = previous_version + 1;
                    let stale_label = Self::get_nodelabel(&uname, true, previous_version);
                    let fresh_label = Self::get_nodelabel(&uname, false, latest_version);
                    let stale_value_to_add = H::hash(&[0u8]);
                    let fresh_value_to_add = H::hash(&Self::value_to_bytes(&val));
                    update_set.push((stale_label, stale_value_to_add));
                    update_set.push((fresh_label, fresh_value_to_add));
                    let new_state = UserState::new(val, latest_version, fresh_label, next_epoch);
                    let mut updatable_states = user_data_val.states.clone();
                    updatable_states.push(new_state);
                    user_data_update_set.push((
                        uname,
                        UserData {
                            states: updatable_states,
                        },
                    ));
                }
            }
        }
        let insertion_set = update_set.iter().map(|(x, y)| (*x, *y)).collect();
        // ideally the azks and the state would be updated together.
        // It may also make sense to have a temp version of the server's database
        let output = self.azks.batch_insert_leaves(insertion_set);
        // Not sure how to remove clones from here?
        user_data_update_set.iter_mut().for_each(|(x, y)| {
            self.user_data.insert(x.clone(), y.clone());
        });
        self.current_epoch = next_epoch;
        output
        // At the moment the tree root is not being written anywhere. Eventually we
        // want to change this to call a write operation to post to a blockchain or some such thing
    }

    // Provides proof for correctness of latest version
    pub fn lookup(&self, uname: Username) -> Result<LookupProof<H>, SeemlessError> {
        // FIXME: restore with: LookupProof<H> {
        // FIXME: this code won't work
        let data = &self.user_data.get(&uname);
        match data {
            None => {
                // Need to throw an error
                Err(SeemlessError::SeemlessDirectoryErr(
                    SeemlessDirectoryError::LookedUpNonExistentUser(uname.0, self.current_epoch),
                ))
            }
            Some(user_data_val) => {
                // Need to account for the case where the latest state is
                // added but the database is in the middle of an update
                let latest_st = user_data_val.states.last().unwrap();
                let plaintext_value = latest_st.plaintext_val.clone();
                let current_version = latest_st.version;
                let marker_version = Self::get_marker_version(current_version);
                let existent_label = Self::get_nodelabel(&uname, false, current_version);
                let non_existent_label = Self::get_nodelabel(&uname, true, current_version);
                let marker_label = Self::get_nodelabel(&uname, false, marker_version);
                let existence_proof = self
                    .azks
                    .get_membership_proof(existent_label, self.current_epoch);
                let freshness_proof = self
                    .azks
                    .get_non_membership_proof(non_existent_label, self.current_epoch);
                let marker_proof = self
                    .azks
                    .get_membership_proof(marker_label, self.current_epoch);
                Ok(LookupProof {
                    epoch: self.current_epoch,
                    plaintext_value,
                    version: current_version,
                    existence_proof,
                    marker_proof,
                    freshness_proof,
                })
            }
        }
        // unimplemented!()
        // S::get("0".to_string()).unwrap();
        // Ok(())
    }

    pub fn lookup_verify(
        &self,
        uname: Username,
        proof: LookupProof<H>,
    ) -> Result<(), SeemlessDirectoryError> {
        let epoch = proof.epoch;
        let root_node = self.azks.get_root_hash_at_epoch(epoch).unwrap();
        // pub struct LookupProof<H: Hasher> {
        //     plaintext_value: Values,
        //     version: u64,
        //     existence_proof: MembershipProof<H>,
        //     marker_proof: MembershipProof<H>,
        //     freshness_proof: NonMembershipProof<H>,
        // }
        let plaintext_value = proof.plaintext_value;
        let _curr_value = H::hash(&Self::value_to_bytes(&plaintext_value));
        let version = proof.version;
        let marker_version = 1 << Self::get_marker_version(version);
        let existence_proof = proof.existence_proof;
        let marker_proof = proof.marker_proof;
        let freshness_proof = proof.freshness_proof;

        let existence_label = Self::get_nodelabel(&uname, false, version);
        assert!(existence_label != existence_proof.label);
        let non_existence_label = Self::get_nodelabel(&uname, true, version);
        assert!(non_existence_label != freshness_proof.label);
        let marker_label = Self::get_nodelabel(&uname, false, marker_version);
        assert!(marker_label != marker_proof.label);

        assert!(
            self.azks
                .verify_membership(root_node, epoch, existence_proof),
            "Existence proof did not verify!"
        );
        assert!(
            self.azks.verify_membership(root_node, epoch, marker_proof),
            "Marker proof did not verify!"
        );
        assert!(
            self.azks
                .verify_nonmembership(non_existence_label, root_node, epoch, freshness_proof),
            "Freshness proof did not verify!"
        );

        Ok(())
        // unimplemented!()
    }

    /// Takes in the current state of the server and a label.
    /// If the label is present in the current state,
    /// this function returns all the values ever associated with it,
    /// and the epoch at which each value was first committed to the server state.
    /// It also returns the proof of the latest version being served at all times.
    pub fn key_history(&self, uname: &Username) -> Result<HistoryProof<H>, SeemlessError> {
        // pub struct UpdateProof<H: Hasher> {
        //     epoch: u64,
        //     plaintext_value: Values,
        //     version: u64,
        //     existence_at_ep: MembershipProof<H>, // membership proof to show that the key was included in this epoch
        //     previous_val_stale_at_ep: MembershipProof<H>, // proof that previous value was set to old at this epoch
        //     non_existence_before_ep: NonMembershipProof<H>, // proof that this value didn't exist prior to this ep
        //     non_existence_of_next_few: Vec<NonMembershipProof<H>>, // proof that the next few values did not exist at this time
        //     non_existence_of_future_markers: Vec<NonMembershipProof<H>>, // proof that future markers did not exist
        // }

        // pub struct HistoryProof<H: Hasher> {
        //     proofs: Vec<UpdateProof<H>>,
        // }
        let username = uname.0.to_string();
        let this_user_data =
            self.user_data
                .get(uname)
                .ok_or(SeemlessDirectoryError::LookedUpNonExistentUser(
                    username,
                    self.current_epoch,
                ))?;
        let mut proofs = Vec::<UpdateProof<H>>::new();
        for user_state in &this_user_data.states {
            let proof = self._create_single_update_proof(uname, user_state)?;

            proofs.push(proof);
        }
        Ok(HistoryProof { proofs })
    }

    pub fn key_history_verify(
        &self,
        _uname: Username,
        _proof: HistoryProof<H>,
    ) -> Result<(), SeemlessDirectoryError> {
        unimplemented!()
    }

    pub fn audit(
        &self,
        _audit_start_ep: u64,
        _audit_end_ep: u64,
    ) -> Result<Vec<AppendOnlyProof<H>>, SeemlessDirectoryError> {
        unimplemented!()
    }

    pub fn audit_verify(
        &self,
        _audit_start_ep: u64,
        _audit_end_ep: u64,
        _proof: HistoryProof<H>,
    ) -> Result<(), SeemlessDirectoryError> {
        unimplemented!()
    }

    /// HELPERS ///

    fn username_to_nodelabel(_uname: &Username) -> NodeLabel {
        // this function will need to read the VRF key off some function
        unimplemented!()
    }

    fn get_nodelabel(_uname: &Username, _stale: bool, _version: u64) -> NodeLabel {
        // this function will need to read the VRF key off some function
        unimplemented!()
    }

    fn value_to_bytes(_value: &Values) -> [u8; 64] {
        unimplemented!()
    }

    fn get_marker_version(version: u64) -> u64 {
        (64 - version.leading_zeros() - 1).into()
    }

    fn _create_single_update_proof(
        &self,
        uname: &Username,
        user_state: &UserState,
    ) -> Result<UpdateProof<H>, SeemlessError> {
        let epoch = user_state.epoch;
        let plaintext_value = &user_state.plaintext_val;
        let version = &user_state.version;

        let label_at_ep = Self::get_nodelabel(uname, false, *version);
        let prev_label_at_ep = Self::get_nodelabel(uname, true, *version);

        let existence_at_ep = self.azks.get_membership_proof(label_at_ep, epoch);
        let previous_val_stale_at_ep = self.azks.get_membership_proof(prev_label_at_ep, epoch);
        let non_existence_before_ep = self.azks.get_non_membership_proof(label_at_ep, epoch - 1);

        let next_marker = Self::get_marker_version(*version) + 1;
        let final_marker = Self::get_marker_version(epoch);

        let mut non_existence_of_next_few = Vec::<NonMembershipProof<H>>::new();

        for ver in version + 1..(1 << next_marker) {
            let label_for_ver = Self::get_nodelabel(uname, false, ver);
            let non_existence_of_ver = self.azks.get_non_membership_proof(label_for_ver, epoch);
            non_existence_of_next_few.push(non_existence_of_ver);
        }

        let mut non_existence_of_future_markers = Vec::<NonMembershipProof<H>>::new();

        for marker_power in next_marker..final_marker + 1 {
            let ver = 1 << marker_power;
            let label_for_ver = Self::get_nodelabel(uname, false, ver);
            let non_existence_of_ver = self.azks.get_non_membership_proof(label_for_ver, epoch);
            non_existence_of_future_markers.push(non_existence_of_ver);
        }

        Ok(UpdateProof {
            epoch,
            plaintext_value: plaintext_value.clone(),
            version: *version,
            existence_at_ep,
            previous_val_stale_at_ep,
            non_existence_before_ep,
            non_existence_of_next_few,
            non_existence_of_future_markers,
        })
    }

    pub fn _verify_single_update_proof(
        &self,
        proof: UpdateProof<H>,
        uname: &Username,
    ) -> Result<(), SeemlessError> {
        let epoch = proof.epoch;
        let plaintext_value = proof.plaintext_value;
        let version = proof.version;
        let label_at_ep = Self::get_nodelabel(uname, false, version);
        let prev_label_at_ep = Self::get_nodelabel(uname, true, version);
        let existence_at_ep = proof.existence_at_ep;
        let previous_val_stale_at_ep = proof.previous_val_stale_at_ep;

        let non_existence_before_ep = proof.non_existence_before_ep;
        let root_hash = self.azks.get_root_hash_at_epoch(epoch)?;

        if label_at_ep != existence_at_ep.label {
            return Err(SeemlessError::SeemlessDirectoryErr(
                SeemlessDirectoryError::KeyHistoryVerificationErr(
                    format!("Label of user {:?}'s version {:?} at epoch {:?} does not match the one in the proof",
                    uname, version, epoch))));
        }
        if !self.azks
            .verify_membership(root_hash, epoch, existence_at_ep) {
                return Err(SeemlessError::SeemlessDirectoryErr(
                    SeemlessDirectoryError::KeyHistoryVerificationErr(
                        format!("Existence proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                        uname, version, epoch))));
            }
        // Edge case here! We need to account for version = 1 where the previous version won't have a proof.
        if !self.azks
        .verify_membership(root_hash, epoch, previous_val_stale_at_ep) {
            return Err(SeemlessError::SeemlessDirectoryErr(
                SeemlessDirectoryError::KeyHistoryVerificationErr(
                    format!("Staleness proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                    uname, version-1, epoch))));
        }
        if !self.azks.verify_nonmembership(label_at_ep, root_hash, epoch - 1, non_existence_before_ep) {
            return Err(SeemlessError::SeemlessDirectoryErr(
                SeemlessDirectoryError::KeyHistoryVerificationErr(
                    format!("Non-existence before epoch proof of user {:?}'s version {:?} at epoch {:?} does not verify",
                    uname, version, epoch-1))));
        }

        let next_marker = Self::get_marker_version(version) + 1;
        let final_marker = Self::get_marker_version(epoch);
        // for (i, ver) in (version + 1..(1 << next_marker)).enumerate() {
        //     let label_for_ver = Self::get_nodelabel(uname, false, ver);
        //     let pf = proof.non_existence_of_next_few[i];
        //     if !self.azks.verify_nonmembership(label_at_ep, root_hash, epoch - 1, pf) {
        //         return Err(SeemlessError::SeemlessDirectoryErr(
        //             SeemlessDirectoryError::KeyHistoryVerificationErr(
        //                 format!("Non-existence before epoch proof of user {:?}'s version {:?} at epoch {:?} does not verify",
        //                 uname, version, epoch-1))));
        //     }
        // }



        Ok(())
        // unimplemented!()
    }
}

// #[cfg(test)]
// mod tests {

//     use crypto::hashers::Blake3_256;

//     use math::fields::f128::BaseElement;

//     type Blake3 = Blake3_256<BaseElement>;

//     // #[test]
//     // fn test_simple_publish() -> Result<(), SeemlessDirectoryError> {
//     //     SeemlessDirectory::<InMemoryDb, Blake3>::publish(vec![(
//     //         Username("hello".to_string()),
//     //         Values("world".to_string()),
//     //     )])?;
//     //     SeemlessDirectory::<InMemoryDb, Blake3>::lookup(Username("hello".to_string()))?;

//     //     Ok(())
//     // }
// }
