-------------------------- MODULE CerberusNullBroken --------------------------
EXTENDS CerberusNull

BrokenNext == Next \/ UnsafeExecuteWithoutCapability
BrokenSpec == Init /\ [][BrokenNext]_vars

=============================================================================
