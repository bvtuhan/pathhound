use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum_macros::EnumString;

#[derive(Debug, Clone, PartialEq, Eq, Hash, EnumString, Deserialize, Serialize)]
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
    AdLocalGroup,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EnumString, Deserialize, Serialize)]
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

#[allow(dead_code)]
impl Relationship {
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
}

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

#[derive(Debug, Deserialize, Clone)]
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

impl From<GraphResponse> for petgraph::Graph<Node, Relationship> {
    fn from(value: GraphResponse) -> Self {
        let mut graph = petgraph::Graph::<Node, Relationship>::new();
        let mut node_map: HashMap<&str, petgraph::prelude::NodeIndex> =
            HashMap::with_capacity(value.data.nodes.len());

        for (node_id, node_info) in &value.data.nodes {
            node_map
                .entry(node_id)
                .or_insert_with(|| graph.add_node(node_info.clone()));
        }

        for edge in &value.data.edges {
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
