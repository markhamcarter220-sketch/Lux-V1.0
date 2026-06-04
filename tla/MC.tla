---- MODULE MC ----
(*
  MC.tla -- Model-checking wrapper for LuxKernel.

  Bounds:
    AllRights    = {"DELEGATE","SHUTDOWN"}  -> SUBSET = 4 subsets
    Principals   = {P1, P2}
    Nodes        = {N1, N2}
    MaxNonce     = 2
    MaxResources = 2
    MaxEpoch     = 1
    MaxCaps      = 3   <- hard cap on issuedCaps size; keeps state space finite
    BootEdges    = {N1->N2}
*)

EXTENDS LuxKernel

MCAllRights    == {"DELEGATE", "SHUTDOWN"}
MCPrincipals   == {"P1", "P2"}
MCNodes        == {"N1", "N2"}
MCMaxNonce     == 2
MCMaxResources == 2
MCMaxEpoch     == 1
MCMaxCaps      == 3
MCBootEdges    == {<<"N1", "N2">>}

====
