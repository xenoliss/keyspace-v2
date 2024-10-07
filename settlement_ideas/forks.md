Day 0:
    preconfirmedRecords: {
        FORK_0: [ValueHashA]
    }
Day 1:
    preconfirmedRecords: {
        FORK_0: [ValueHashA, ValueHashAB]
    }
Day 2:
    preconfirmedRecords: {
        FORK_0: [ValueHashA, ValueHashAB, ValueHashABC, ValueHashABCD]
    }
Day 3:
    preconfirmedRecords: {
        FORK_0: [ValueHashA, ValueHashAB, ValueHashABC, || ValueHashABCD, ValueHashABCDE]
    }
Day 4:
    preconfirmedRecords: {
        FORK_0: [ValueHashA, ValueHashAB, ValueHashABC, || ValueHashABCD, ValueHashABCDE, ValueHashABCDEF]
    }

preconfirmedRecords: {
    FORK_0: [ValueHashA, ValueHashAB, ValueHashABC, || ValueHashABCD, ValueHashABCDE, ValueHashABCDEF]
}


GET BEHAVIOR:

---- epoch X+1 (settled Day 0) ----
Day 5:
    Root: R5 includes ValueHashA
    If I want to use ValueHashABCDEF I need to prove that ValueHashA is in my latest fork list.


---- epoch X+2 (settled Day 1) ----
Day 6:
    Root: R6 includes ValueHashAB
    If I want to use ValueHashABCDEF I need to prove that ValueHashAB is in my latest fork list.


---- epoch X+3 (settled Day 2) ----
Day 7:
    Root: R7 includes ValueHashABC (BUT NOT ValueHashABCD)
    If I want to use ValueHashABCDEF I need to prove that ValueHashABC is in my latest fork list.


---- epoch X+4 (settled Day 3) ----
Day 8:
    Root: R8 includes ValueHashABC1 (BUT NOT ValueHashABCD)
    If I want to use ValueHashABC1 I need to prove that ValueHashABC1 is NOT in my latest fork list.
    (this can be done by providing the index of the conflicting nonce)


---- epoch X+4 (settled Day 4) ----
Day 9:
    Root: R9 includes ValueHashABC1
    If I want to use ValueHashABC1 I need to prove that ValueHashABC1 is NOT in my latest fork list.
    (this can be done by providing the index of the conflicting nonce)



SET BEHAVIOR


Day 12:
    Root: R12 includes ValueHashABC1
    
    I want to perform a signer update to ValueHashABC1_A. I need to prove that my latest valid state is ValueHashABC1, and invalidate my previous fork. This can be done by proving that ValueHashABC1 is NOT in my latest fork list (by providing the conflicting nonce)
    
    preconfirmedRecords: {
        FORK_0: [ValueHashA, ValueHashAB, ValueHashABC, || ValueHashABCD, ValueHashABCDE, ValueHashABCDEF],
        FORK_1: [ValueHashABC1, ValueHashABC1_A],
    }

   

Day 13:
    Root: R13 includes ValueHashABC1

    I want to perform a signer update to ValueHashABC1_B. I need to prove that ValueHashABC1 is in my latest fork list and use its last ValueHash as my current one.
    
    preconfirmedRecords: {
        FORK_0: [ValueHashA, ValueHashAB, ValueHashABC, || ValueHashABCD, ValueHashABCDE, ValueHashABCDEF],
        FORK_1: [ValueHashABC1, ValueHashABC1_A],
    }
