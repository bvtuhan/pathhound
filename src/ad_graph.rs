use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt,
};
use strum_macros::{EnumString, IntoStaticStr};

pub(crate) type ADGraph = petgraph::Graph<Node, Relationship>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, EnumString, Deserialize, Serialize, IntoStaticStr)]
#[allow(non_camel_case_types, dead_code)]
pub(crate) enum NodeType {
    AIACA,
    AZApp,
    AZAutomationAccount,
    AZBase,
    AZContainerRegistry,
    AZDevice,
    AZFederatedIdentityCredential,
    AZFunctionApp,
    AZGroup,
    AZKeyVault,
    AZLogicApp,
    AZManagedCluster,
    AZManagementGroup,
    AZResourceGroup,
    AZRole,
    AZServicePrincipal,
    AZSubscription,
    AZTenant,
    AZUser,
    AZVM,
    AZVMScaleSet,
    AZWebApp,
    Base,
    CertTemplate,
    Computer,
    Container,
    Domain,
    EnterpriseCA,
    GPO,
    Group,
    IssuancePolicy,
    Meta,
    NTAuthStore,
    OU,
    RootCA,
    User,
    ADLocalGroup,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EnumString, Deserialize, Serialize, IntoStaticStr)]
#[allow(non_camel_case_types, dead_code)]
pub(crate) enum Relationship {
    AbuseTGTDelegation,
    ADCSESC1,
    ADCSESC10a,
    ADCSESC10b,
    ADCSESC13,
    ADCSESC3,
    ADCSESC4,
    ADCSESC6a,
    ADCSESC6b,
    ADCSESC9a,
    ADCSESC9b,
    AddAllowedToAct,
    AddKeyCredentialLink,
    AddMember,
    AddSelf,
    AdminTo,
    AllExtendedRights,
    AllowedToAct,
    AllowedToDelegate,
    AZAddMembers,
    AZAddOwner,
    AZAddSecret,
    AZAKSContributor,
    AZAppAdmin,
    AZAuthenticatesTo,
    AZAutomationContributor,
    AZAvereContributor,
    AZCloudAppAdmin,
    AZContains,
    AZContributor,
    AZExecuteCommand,
    AZGetCertificates,
    AZGetKeys,
    AZGetSecrets,
    AZGlobalAdmin,
    AZHasRole,
    AZKeyVaultKVContributor,
    AZLogicAppContributor,
    AZManagedIdentity,
    AZMemberOf,
    AZMGAddMember,
    AZMGAddOwner,
    AZMGAddSecret,
    AZMGAppRoleAssignment_ReadWrite_All,
    AZMGApplication_ReadWrite_All,
    AZMGDirectory_ReadWrite_All,
    AZMGGrantAppRoles,
    AZMGGrantRole,
    AZMGGroupMember_ReadWrite_All,
    AZMGGroup_ReadWrite_All,
    AZMGRoleManagement_ReadWrite_Directory,
    AZMGServicePrincipalEndpoint_ReadWrite_All,
    AZNodeResourceGroup,
    AZOwner,
    AZOwns,
    AZPrivilegedAuthAdmin,
    AZPrivilegedRoleAdmin,
    AZResetPassword,
    AZRoleApprover,
    AZRoleEligible,
    AZRunsAs,
    AZScopedTo,
    AZUserAccessAdministrator,
    AZVMAdminLogin,
    AZVMContributor,
    AZWebsiteContributor,
    CanPSRemote,
    CanRDP,
    ClaimSpecialIdentity,
    CoerceAndRelayNTLMToADCS,
    CoerceAndRelayNTLMToLDAP,
    CoerceAndRelayNTLMToLDAPS,
    CoerceAndRelayNTLMToSMB,
    CoerceToTGT,
    Contains,
    CrossForestTrust,
    DCFor,
    DCSync,
    DelegatedEnrollmentAgent,
    DumpSMSAPassword,
    Enroll,
    EnrollOnBehalfOf,
    EnterpriseCAFor,
    ExecuteDCOM,
    ExtendedByPolicy,
    ForceChangePassword,
    GenericAll,
    GenericWrite,
    GetChanges,
    GetChangesAll,
    GetChangesInFilteredSet,
    GoldenCert,
    GPLink,
    HasSession,
    HasSIDHistory,
    HasTrustKeys,
    HostsCAService,
    IssuedSignedBy,
    LocalToComputer,
    ManageCA,
    ManageCertificates,
    MemberOf,
    MemberOfLocalGroup,
    NTAuthStoreFor,
    OIDGroupLink,
    Owns,
    OwnsLimitedRights,
    OwnsRaw,
    ProtectAdminGroups,
    PublishedTo,
    ReadGMSAPassword,
    ReadLAPSPassword,
    RemoteInteractiveLogonRight,
    RootCAFor,
    SameForestTrust,
    SpoofSIDHistory,
    SQLAdmin,
    SyncLAPSPassword,
    SyncedToADUser,
    SyncedToEntraUser,
    TrustedForNTAuth,
    WriteAccountRestrictions,
    WriteDacl,
    WriteGPLink,
    WriteOwner,
    WriteOwnerLimitedRights,
    WriteOwnerRaw,
    WritePKIEnrollmentFlag,
    WritePKINameFlag,
    WriteSPN,
}

impl fmt::Display for Relationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // let string: &'static str = (self).into();
        write!(f, "{:?}({})", &self, self.cost())
    }
}

#[allow(dead_code)]
impl Relationship {
    /// Determines if a relationship is traversable for attack pathfinding purposes.
    pub(crate) fn is_traversable(&self) -> bool {
        matches!(
            self,
            Relationship::AbuseTGTDelegation
                | Relationship::ADCSESC1
                | Relationship::ADCSESC10a
                | Relationship::ADCSESC10b
                | Relationship::ADCSESC13
                | Relationship::ADCSESC3
                | Relationship::ADCSESC4
                | Relationship::ADCSESC6a
                | Relationship::ADCSESC6b
                | Relationship::ADCSESC9a
                | Relationship::ADCSESC9b
                | Relationship::AddAllowedToAct
                | Relationship::AddKeyCredentialLink
                | Relationship::AddMember
                | Relationship::AddSelf
                | Relationship::AdminTo
                | Relationship::AllExtendedRights
                | Relationship::AllowedToAct
                | Relationship::AllowedToDelegate
                | Relationship::CanPSRemote
                | Relationship::CanRDP
                | Relationship::ClaimSpecialIdentity
                | Relationship::CoerceAndRelayNTLMToADCS
                | Relationship::CoerceAndRelayNTLMToLDAP
                | Relationship::CoerceAndRelayNTLMToLDAPS
                | Relationship::CoerceAndRelayNTLMToSMB
                | Relationship::CoerceToTGT
                | Relationship::Contains
                | Relationship::CrossForestTrust
                | Relationship::DCFor
                | Relationship::DCSync
                | Relationship::DumpSMSAPassword
                | Relationship::ExecuteDCOM
                | Relationship::ForceChangePassword
                | Relationship::GenericAll
                | Relationship::GenericWrite
                | Relationship::GoldenCert
                | Relationship::GPLink
                | Relationship::HasSIDHistory
                | Relationship::HasSession
                | Relationship::HasTrustKeys
                | Relationship::ManageCA
                | Relationship::ManageCertificates
                | Relationship::MemberOf
                | Relationship::Owns
                | Relationship::OwnsLimitedRights
                | Relationship::ReadGMSAPassword
                | Relationship::ReadLAPSPassword
                | Relationship::SameForestTrust
                | Relationship::SpoofSIDHistory
                | Relationship::SQLAdmin
                | Relationship::SyncedToADUser
                | Relationship::SyncedToEntraUser
                | Relationship::SyncLAPSPassword
                | Relationship::WriteAccountRestrictions
                | Relationship::WriteDacl
                | Relationship::WriteGPLink
                | Relationship::WriteOwner
                | Relationship::WriteOwnerLimitedRights
                | Relationship::WriteSPN
        )
    }

    /// Custom cost function for relationships, used in attack pathfinding to prioritize certain relationships over others.
    ///
    /// Copied from <https://github.com/AD-Security/AD_Miner/blob/main/ad_miner/sources/modules/exploitability_ratings.json>
    pub fn cost(&self) -> usize {
        match self {
            Relationship::AddAllowedToAct => 40,
            Relationship::AddKeyCredentialLink => 5,
            Relationship::AddMember => 10,
            Relationship::AddSelf => 10,
            Relationship::AdminTo => 5,
            Relationship::AllExtendedRights => 30,
            Relationship::AllowedToAct => 15,
            Relationship::AllowedToDelegate => 30,
            Relationship::AZAddMembers => 10,
            Relationship::AZAddOwner => 30,
            Relationship::AZAddSecret => 30,
            Relationship::AZAKSContributor => 80,
            Relationship::AZAppAdmin => 50,
            Relationship::AZAutomationContributor => 80,
            Relationship::AZAvereContributor => 100,
            Relationship::AZCloudAppAdmin => 100,
            Relationship::AZContains => 60,
            Relationship::AZContributor => 20,
            Relationship::AZExecuteCommand => 50,
            Relationship::AZGetCertificates => 30,
            Relationship::AZGetKeys => 30,
            Relationship::AZGetSecrets => 30,
            Relationship::AZGlobalAdmin => 5,
            Relationship::AZHasRole => 50,
            Relationship::AZLogicAppContributor => 60,
            Relationship::AZManagedIdentity => 70,
            Relationship::AZMemberOf => 0,
            Relationship::AZMGAddMember => 20,
            Relationship::AZMGAddOwner => 20,
            Relationship::AZMGAddSecret => 30,
            Relationship::AZMGApplication_ReadWrite_All => 50,
            Relationship::AZMGAppRoleAssignment_ReadWrite_All => 100,
            Relationship::AZMGDirectory_ReadWrite_All => 100,
            Relationship::AZMGGrantAppRoles => 80,
            Relationship::AZMGGrantRole => 30,
            Relationship::AZMGGroupMember_ReadWrite_All => 100,
            Relationship::AZMGGroup_ReadWrite_All => 100,
            Relationship::AZMGRoleManagement_ReadWrite_Directory => 100,
            Relationship::AZMGServicePrincipalEndpoint_ReadWrite_All => 100,
            Relationship::AZNodeResourceGroup => 80,
            Relationship::AZOwns => 40,
            Relationship::AZPrivilegedAuthAdmin => 30,
            Relationship::AZPrivilegedRoleAdmin => 20,
            Relationship::AZResetPassword => 30,
            Relationship::AZRunsAs => 40,
            Relationship::AZUserAccessAdministrator => 50,
            Relationship::AZVMAdminLogin => 10,
            Relationship::AZVMContributor => 10,
            Relationship::AZWebsiteContributor => 90,
            Relationship::CanPSRemote => 100,
            Relationship::CanRDP => 80,
            Relationship::ClaimSpecialIdentity => 0,
            Relationship::CoerceAndRelayNTLMToADCS => 10,
            Relationship::CoerceAndRelayNTLMToLDAP => 20,
            Relationship::CoerceAndRelayNTLMToLDAPS => 20,
            Relationship::CoerceAndRelayNTLMToSMB => 10,
            Relationship::CoerceToTGT => 50,
            Relationship::Contains => 100,
            Relationship::CrossForestTrust => 100,
            Relationship::DCFor => 100,
            Relationship::DCSync => 0,
            Relationship::DumpSMSAPassword => 50,
            Relationship::Enroll => 40,
            Relationship::EnrollOnBehalfOf => 100,
            Relationship::EnterpriseCAFor => 100,
            Relationship::ExecuteDCOM => 100,
            Relationship::ForceChangePassword => 50,
            Relationship::GenericAll => 5,
            Relationship::GenericWrite => 6,
            Relationship::GetChanges => 15,
            Relationship::GetChangesAll => 15,
            Relationship::GetChangesInFilteredSet => 15,
            Relationship::GoldenCert => 5,
            Relationship::GPLink => 40,
            Relationship::HasSession => 11,
            Relationship::HasSIDHistory => 0,
            Relationship::HasTrustKeys => 30,
            Relationship::HostsCAService => 100,
            Relationship::IssuedSignedBy => 100,
            Relationship::ManageCA => 100,
            Relationship::ManageCertificates => 100,
            Relationship::MemberOf => 0,
            Relationship::MemberOfLocalGroup => 0,
            Relationship::NTAuthStoreFor => 100,
            Relationship::Owns => 11,
            Relationship::OwnsRaw => 11,
            Relationship::ProtectAdminGroups => 15,
            Relationship::PublishedTo => 100,
            Relationship::ReadGMSAPassword => 30,
            Relationship::ReadLAPSPassword => 30,
            Relationship::RemoteInteractiveLogonRight => 100,
            Relationship::RootCAFor => 100,
            Relationship::SameForestTrust => 0,
            Relationship::SpoofSIDHistory => 10,
            Relationship::SQLAdmin => 60,
            Relationship::SyncLAPSPassword => 30,
            Relationship::SyncedToADUser => 50,
            Relationship::SyncedToEntraUser => 50,
            Relationship::TrustedForNTAuth => 100,
            Relationship::WriteAccountRestrictions => 20,
            Relationship::WriteDacl => 10,
            Relationship::WriteGPLink => 40,
            Relationship::WriteOwner => 10,
            Relationship::WriteOwnerRaw => 10,
            Relationship::WriteSPN => 40,
            _ => 1_000_000,
        }
    }
}

/// Main data structure for the graph response from the API,
/// containing nodes and edges representing the Active Directory environment.
#[derive(Debug, Deserialize)]
pub(crate) struct GraphResponse {
    pub data: GraphData,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GraphData {
    pub(crate) edges: Vec<Edge>,
    pub(crate) nodes: HashMap<String, Node>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Edge {
    pub(crate) kind: Relationship,
    pub(crate) source: String,
    pub(crate) target: String,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
pub(crate) struct Node {
    #[serde(rename = "isOwnedObject")]
    pub(crate) is_owned_object: bool,
    #[serde(rename = "isTierZero")]
    pub(crate) is_tier_zero: bool,
    pub(crate) kind: NodeType,
    #[serde(rename = "label")]
    pub(crate) name: String,
    #[serde(rename = "objectId")]
    pub(crate) object_id: String,
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let node_type: &'static str = (&self.kind).into();
        let tier_zero = if self.is_tier_zero { "(★)" } else { "" };
        write!(f, "{}({}{})", node_type, self.name, tier_zero)
    }
}

impl GraphResponse {
    /// Converts the deserialized graph response into a petgraph::Graph (ADGraph). Nodes have the type [`Node`]
    /// and edges have the type [`Relationship`]. The `filter_non_traversable_edges` parameter
    // allows for excluding edges that are not traversable for attack pathfinding, which is set to `true` by default.
    pub(crate) fn to_graph(self, filter_non_traversable_edges: bool) -> ADGraph {
        let mut graph = ADGraph::new();
        let mut node_map: HashMap<&str, petgraph::prelude::NodeIndex> =
            HashMap::with_capacity(self.data.nodes.len());

        for (node_id, node_info) in &self.data.nodes {
            node_map
                .entry(node_id)
                .or_insert_with(|| graph.add_node(node_info.clone()));
        }

        for edge in &self.data.edges {
            if filter_non_traversable_edges && !edge.kind.is_traversable() {
                continue;
            }

            let source_node = node_map
                .get(edge.source.as_str())
                .expect("Expected source node to exist");
            let target_node = node_map
                .get(edge.target.as_str())
                .expect("Expected target node to exist");

            let _ = graph.add_edge(*source_node, *target_node, edge.kind.to_owned());
        }

        graph
    }
}

/// Custom petgraph extension for custom attack graph functionalities
pub(crate) trait ADGraphExt {
    /// Creates a subgraph containing the cheapest attack paths between the specified start and target nodes.
    ///
    /// This method uses the A* algorithm to find the shortest paths based on the custom cost function
    /// defined in the `Relationship` enum.
    fn create_attack_graph(&self, start_nodes: &[&Node], target_nodes: &[&Node]) -> Self;

    /// Finds all nodes that are domain admins, which is determined by checking if the object ID ends with "-512".
    fn find_domain_admins(&self) -> Vec<&Node>;

    /// Finds the cheapest relationship between two nodes, which is used in the `create_attack_graph` method
    /// to ensure that only the most relevant edges are included in the attack graph.
    fn find_min_relationship(
        &self,
        start_node: petgraph::prelude::NodeIndex,
        target_node: petgraph::prelude::NodeIndex,
    ) -> Option<Relationship>;

    /// Returns the index of a node in the graph if it exists,
    /// which is used in the `run_astar` method to convert from node references to graph indices for pathfinding.
    fn find_node_index(&self, node: &Node) -> Option<petgraph::prelude::NodeIndex>;

    /// Returns a reference to the first node that matches the given value (either name or object ID).
    fn find_node(&self, value: impl AsRef<str>) -> Option<&Node>;

    /// Finds all tier-zero nodes used for template-based attack pathfinding
    fn find_tier_zero_nodes(&self) -> Vec<&Node>;

    /// Finds all non-tier-zero nodes used for template-based attack pathfinding
    fn find_non_tier_zero_nodes(&self) -> Vec<&Node>;

    /// The main graph traversal algorithm for finding cheapest attack path between two nodes.
    fn run_astar(
        &self,
        start_node: &Node,
        target_node: &Node,
    ) -> Option<(usize, Vec<petgraph::prelude::NodeIndex>)>;
}

impl ADGraphExt for ADGraph {
    fn create_attack_graph(&self, start_nodes: &[&Node], target_nodes: &[&Node]) -> Self {
        let mut subgraph = Self::new();
        let mut node_map =
            HashMap::<petgraph::prelude::NodeIndex, petgraph::prelude::NodeIndex>::new();

        let mut visited_edges = HashSet::new();

        for (source_node, target_node) in start_nodes.iter().cartesian_product(target_nodes) {
            let shortest_path = self.run_astar(source_node, target_node);
            if let Some((_, path)) = shortest_path {
                let path_pairs = path.windows(2);
                for pair_ptr in path_pairs {
                    let source_idx = pair_ptr[0];
                    let target_idx = pair_ptr[1];
                    let subgraph_source_idx = match node_map.get(&source_idx) {
                        Some(&idx) => idx,
                        None => {
                            let weight = self.node_weight(source_idx).unwrap();
                            let idx = subgraph.add_node(weight.clone());
                            node_map.insert(source_idx, idx);
                            idx
                        }
                    };
                    let subgraph_target_idx = match node_map.get(&target_idx) {
                        Some(&idx) => idx,
                        None => {
                            let weight = self.node_weight(target_idx).unwrap();
                            let idx = subgraph.add_node(weight.clone());
                            node_map.insert(target_idx, idx);
                            idx
                        }
                    };

                    let min_rel = self.find_min_relationship(source_idx, target_idx);

                    if let Some(min_rel) = min_rel {
                        let src_target_rel =
                            (subgraph_source_idx, subgraph_target_idx, min_rel.clone());
                        if !visited_edges.contains(&src_target_rel) {
                            visited_edges.insert(src_target_rel);
                            subgraph.add_edge(subgraph_source_idx, subgraph_target_idx, min_rel);
                        }
                    }
                }
            }
        }

        subgraph
    }

    fn run_astar(
        &self,
        start_node: &Node,
        target_node: &Node,
    ) -> Option<(usize, Vec<petgraph::prelude::NodeIndex>)> {
        let start_idx = self
            .find_node_index(start_node)
            .expect("Failed to find the index of the start node");
        let target_idx = self
            .find_node_index(target_node)
            .expect("Failed to find the index of the target node");

        petgraph::algo::astar(
            self,
            start_idx,
            |target| target == target_idx,
            |edge| edge.weight().cost(),
            |_| 0,
        )
    }

    fn find_node_index(&self, node: &Node) -> Option<petgraph::prelude::NodeIndex> {
        self.node_indices()
            .find(|node_idx| node.eq(self.node_weight(*node_idx).unwrap()))
    }

    fn find_min_relationship(
        &self,
        start_node: petgraph::prelude::NodeIndex,
        target_node: petgraph::prelude::NodeIndex,
    ) -> Option<Relationship> {
        let relationships = self.edges_connecting(start_node, target_node);

        relationships
            .min_by_key(|rel| rel.weight().cost())
            .map(|rel| rel.weight().to_owned())
    }

    fn find_node(&self, value: impl AsRef<str>) -> Option<&Node> {
        self.raw_nodes()
            .iter()
            .find(|node| {
                let weight = &node.weight;
                let value = value.as_ref();
                weight.name.eq_ignore_ascii_case(value)
                    || weight.object_id.eq_ignore_ascii_case(value)
            })
            .map(|node| &node.weight)
    }

    fn find_domain_admins(&self) -> Vec<&Node> {
        self.raw_nodes()
            .iter()
            .filter_map(|node| {
                let weight = &node.weight;
                if weight.object_id.ends_with("-512") {
                    return Some(weight);
                }
                None
            })
            .collect_vec()
    }

    fn find_tier_zero_nodes(&self) -> Vec<&Node> {
        self.raw_nodes()
            .iter()
            .filter_map(|node| {
                let weight = &node.weight;
                if weight.is_tier_zero {
                    return Some(weight);
                }
                None
            })
            .collect_vec()
    }

    fn find_non_tier_zero_nodes(&self) -> Vec<&Node> {
        self.raw_nodes()
            .iter()
            .filter_map(|node| {
                let weight = &node.weight;
                if !weight.is_tier_zero {
                    return Some(weight);
                }
                None
            })
            .collect_vec()
    }
}
