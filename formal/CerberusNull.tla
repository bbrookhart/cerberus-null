----------------------------- MODULE CerberusNull -----------------------------
EXTENDS Naturals, TLC

(*****************************************************************************
The bounded v0.1 authorization state machine. The model intentionally admits
hostile requests, agent-issued capability presentations, invalid approvals,
mid-flight revocation, and emergency-stop engagement. Only independently
validated authority can reach Execute.
*****************************************************************************)

VARIABLES requestState,
          action,
          resource,
          capabilityPresented,
          capabilityIssuer,
          capabilityActive,
          approvalState,
          requestHash,
          approvalHash,
          emergencyStop,
          decision,
          executed,
          auditRecorded

vars == <<requestState, action, resource, capabilityPresented,
          capabilityIssuer, capabilityActive, approvalState, requestHash,
          approvalHash, emergencyStop, decision, executed, auditRecorded>>

Actions == {"safe", "approval", "t4", "unknown"}
Resources == {"scope", "outside"}
Issuers == {"human", "agent"}
ApprovalOutcomes == {"VALID", "EXPIRED", "MISMATCHED"}

Consequential == action \in {"approval", "t4"}
RequiresApproval == action = "approval"
InMissionScope == resource = "scope"
KnownAction == action # "unknown"
ValidCapability == capabilityActive /\ capabilityIssuer = "human"
ApprovalMatches == approvalState = "VALID" /\ approvalHash = requestHash

Init ==
    /\ requestState = "IDLE"
    /\ action = "none"
    /\ resource = "none"
    /\ capabilityPresented = FALSE
    /\ capabilityIssuer = "none"
    /\ capabilityActive = FALSE
    /\ approvalState = "NONE"
    /\ requestHash = "none"
    /\ approvalHash = "none"
    /\ emergencyStop = FALSE
    /\ decision = "NONE"
    /\ executed = FALSE
    /\ auditRecorded = FALSE

Submit ==
    /\ requestState = "IDLE"
    /\ \E nextAction \in Actions,
          nextResource \in Resources,
          presented \in BOOLEAN,
          issuer \in Issuers,
          stopped \in BOOLEAN:
        /\ requestState' = "REQUESTED"
        /\ action' = nextAction
        /\ resource' = nextResource
        /\ capabilityPresented' = presented
        /\ capabilityIssuer' = issuer
        /\ capabilityActive' = FALSE
        /\ approvalState' = "NONE"
        /\ requestHash' = "request-1"
        /\ approvalHash' = "none"
        /\ emergencyStop' = stopped
        /\ decision' = "NONE"
        /\ executed' = FALSE
        /\ auditRecorded' = FALSE

Validate ==
    /\ requestState = "REQUESTED"
    /\ requestState' = "VALIDATED"
    /\ capabilityActive' = (capabilityPresented /\ capabilityIssuer = "human")
    /\ UNCHANGED <<action, resource, capabilityPresented, capabilityIssuer,
                    approvalState, requestHash, approvalHash, emergencyStop,
                    decision, executed, auditRecorded>>

Decide ==
    /\ requestState = "VALIDATED"
    /\ IF ~KnownAction \/ action = "t4"
          THEN /\ requestState' = "NULLIFIED"
               /\ decision' = "NULL"
          ELSE IF emergencyStop /\ Consequential
            THEN /\ requestState' = "NULLIFIED"
                 /\ decision' = "NULL"
            ELSE IF ~ValidCapability \/ ~InMissionScope
              THEN /\ requestState' = "DENIED"
                   /\ decision' = "DENY"
              ELSE IF RequiresApproval
                THEN /\ requestState' = "APPROVAL_PENDING"
                     /\ decision' = "REQUIRE_APPROVAL"
                ELSE /\ requestState' = "AUTHORIZED"
                     /\ decision' = "ALLOW"
    /\ UNCHANGED <<action, resource, capabilityPresented, capabilityIssuer,
                    capabilityActive, approvalState, requestHash, approvalHash,
                    emergencyStop, executed, auditRecorded>>

HumanApproval ==
    /\ requestState = "APPROVAL_PENDING"
    /\ \E outcome \in ApprovalOutcomes:
        /\ approvalState' = outcome
        /\ approvalHash' = IF outcome = "VALID" THEN requestHash ELSE "other-request"
        /\ IF outcome = "VALID"
              THEN /\ requestState' = "AUTHORIZED"
                   /\ decision' = "ALLOW"
              ELSE /\ requestState' = "DENIED"
                   /\ decision' = "DENY"
    /\ UNCHANGED <<action, resource, capabilityPresented, capabilityIssuer,
                    capabilityActive, requestHash, emergencyStop, executed,
                    auditRecorded>>

EngageEmergencyStop ==
    /\ requestState \in {"REQUESTED", "VALIDATED", "APPROVAL_PENDING", "AUTHORIZED"}
    /\ Consequential
    /\ ~emergencyStop
    /\ emergencyStop' = TRUE
    /\ requestState' = "NULLIFIED"
    /\ decision' = "NULL"
    /\ UNCHANGED <<action, resource, capabilityPresented, capabilityIssuer,
                    capabilityActive, approvalState, requestHash, approvalHash,
                    executed, auditRecorded>>

RevokeCapability ==
    /\ requestState \in {"VALIDATED", "APPROVAL_PENDING", "AUTHORIZED"}
    /\ capabilityActive
    /\ capabilityActive' = FALSE
    /\ requestState' = "DENIED"
    /\ decision' = "DENY"
    /\ UNCHANGED <<action, resource, capabilityPresented, capabilityIssuer,
                    approvalState, requestHash, approvalHash, emergencyStop,
                    executed, auditRecorded>>

Execute ==
    /\ requestState = "AUTHORIZED"
    /\ decision = "ALLOW"
    /\ ValidCapability
    /\ InMissionScope
    /\ KnownAction
    /\ action # "t4"
    /\ ~(emergencyStop /\ Consequential)
    /\ (~RequiresApproval \/ ApprovalMatches)
    /\ requestState' = "EXECUTED"
    /\ executed' = TRUE
    /\ auditRecorded' = TRUE
    /\ UNCHANGED <<action, resource, capabilityPresented, capabilityIssuer,
                    capabilityActive, approvalState, requestHash, approvalHash,
                    emergencyStop, decision>>

Reset ==
    /\ requestState \in {"DENIED", "NULLIFIED", "EXECUTED"}
    /\ requestState' = "IDLE"
    /\ action' = "none"
    /\ resource' = "none"
    /\ capabilityPresented' = FALSE
    /\ capabilityIssuer' = "none"
    /\ capabilityActive' = FALSE
    /\ approvalState' = "NONE"
    /\ requestHash' = "none"
    /\ approvalHash' = "none"
    /\ emergencyStop' = FALSE
    /\ decision' = "NONE"
    /\ executed' = FALSE
    /\ auditRecorded' = FALSE

(*****************************************************************************
This transition is intentionally excluded from Next. The mutation model imports
it to prove that F1 detects an authorization-bypass defect.
*****************************************************************************)
UnsafeExecuteWithoutCapability ==
    /\ requestState = "VALIDATED"
    /\ action = "safe"
    /\ resource = "scope"
    /\ ~capabilityActive
    /\ requestState' = "EXECUTED"
    /\ decision' = "ALLOW"
    /\ executed' = TRUE
    /\ auditRecorded' = TRUE
    /\ UNCHANGED <<action, resource, capabilityPresented, capabilityIssuer,
                    capabilityActive, approvalState, requestHash, approvalHash,
                    emergencyStop>>

Next == Submit \/ Validate \/ Decide \/ HumanApproval \/
        EngageEmergencyStop \/ RevokeCapability \/ Execute \/ Reset

Spec == Init /\ [][Next]_vars

F1_UnauthorizedNeverExecutes ==
    executed =>
        ValidCapability /\ InMissionScope /\ KnownAction /\ action # "t4" /\
        ~(emergencyStop /\ Consequential) /\
        (~RequiresApproval \/ ApprovalMatches)

F2_ApprovalRequiredNeverExecutesWithoutMatch ==
    (executed /\ RequiresApproval) => ApprovalMatches

F3_EmergencyStopBlocksConsequentialExecution ==
    (emergencyStop /\ Consequential) => ~executed

F4_AgentCannotIncreaseCapability ==
    capabilityActive => capabilityIssuer = "human"

F5_T4NeverExecutesAutonomously ==
    (action = "t4") => ~executed

F6_ExecutionRequiresAudit == executed => auditRecorded

F7_ApprovalBinding ==
    (executed /\ RequiresApproval) => approvalHash = requestHash

TypeOK ==
    /\ requestState \in {"IDLE", "REQUESTED", "VALIDATED", "APPROVAL_PENDING",
                          "AUTHORIZED", "DENIED", "NULLIFIED", "EXECUTED"}
    /\ action \in Actions \cup {"none"}
    /\ resource \in Resources \cup {"none"}
    /\ capabilityPresented \in BOOLEAN
    /\ capabilityIssuer \in Issuers \cup {"none"}
    /\ capabilityActive \in BOOLEAN
    /\ approvalState \in ApprovalOutcomes \cup {"NONE"}
    /\ emergencyStop \in BOOLEAN
    /\ decision \in {"NONE", "ALLOW", "DENY", "REQUIRE_APPROVAL", "NULL"}
    /\ executed \in BOOLEAN
    /\ auditRecorded \in BOOLEAN

=============================================================================
