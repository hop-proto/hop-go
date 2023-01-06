// +build arm64,!appengine,!gccgo

// Offsets in state
#define _ba  (0*8)
#define _be  (1*8)
#define _bi  (2*8)
#define _bo  (3*8)
#define _bu  (4*8)
#define _ga  (5*8)
#define _ge  (6*8)
#define _gi  (7*8)
#define _go  (8*8)
#define _gu  (9*8)
#define _ka (10*8)
#define _ke (11*8)
#define _ki (12*8)
#define _ko (13*8)
#define _ku (14*8)
#define _ma (15*8)
#define _me (16*8)
#define _mi (17*8)
#define _mo (18*8)
#define _mu (19*8)
#define _sa (20*8)
#define _se (21*8)
#define _si (22*8)
#define _so (23*8)
#define _su (24*8)

// Temporary registers
#define rT1  R7

// Round vars
#define rpState R0
#define rpStack RSP // TODO(dadrian) FP?

#define rDa R2
#define rDe R3
#define rDi R4
#define rDo R5
#define rDu R6

#define rTmp R7

#define rBa R14
#define rBe R15
#define rBi R19
#define rBo R20
#define rBu R21

#define rCa R8 // TODO si
#define rCe R9 // TODO bp
#define rCi rBi
#define rCo rBo
#define rCu R22

#define MOVD_RBI_RCE MOVD rBi, rCe
#define EOR_RT1_RCA EOR rT1, rCa
#define EOR_RT1_RCE EOR rT1, rCe
#define EOR_RBA_RCU EOR rBa, rCu
#define EOR_RBE_RCU EOR rBe, rCu
#define EOR_RDU_RCU EOR rDu, rCu
#define EOR_RDA_RCA EOR rDa, rCa
#define EOR_RDE_RCE EOR rDe, rCe

#define NOTD(addr, offset, reg) \
    MOVD (offset)(addr), reg \
    MVN reg, reg \
    MOVD reg, (offset)(addr) \

#define XORDA(addr, offset, tmp, out) \
    MOVD (offset)(addr), tmp \
    EOR tmp, out \

#define mKeccakRound(iState, oState, rc, B_RBI_RCE, G_RT1_RCA, G_RT1_RCE, G_RBA_RCU, K_RT1_RCA, K_RT1_RCE, K_RBA_RCU, M_RT1_RCA, M_RT1_RCE, M_RBE_RCU, S_RDU_RCU, S_RDA_RCA, S_RDE_RCE) \
	/* Prepare round */       \
	MOVD rCe, rDa             \
    EOR rDa@>(64-1), ZR, rDa  \
                              \
    MOVD _bi(iState), rCi     \
    MOVD _gi(iState), rTmp    \
    EOR rTmp, rDi             \
    EOR rCu, rDa              \
    MOVD _ki(iState), rTmp    \
    EOR rTmp, rCi             \
    MOVD _mi(iState), rTmp    \
    EOR rTmp, rDi             \
    EOR rDi, rCi              \
                              \
    MOVD rCi, rDe             \
    EOR rDe@>(64-1), ZR, rDe  \
                              \
    MOVD _bo(iState), rCo     \
    MOVD _go(iState), rTmp    \
    EOR rTmp, rDo             \
    EOR rCa, rDe              \
    MOVD _ko(iState), rTmp    \
    EOR rTmp, rCo             \
    MOVD _mo(iState), rTmp    \
    EOR rTmp, rDo             \
    EOR rDo, rCo              \
                              \
    MOVD rCo, rDi             \
    EOR rDi@>(64-1), ZR, rDi  \
                              \
    MOVD rCu, rDo             \
    EOR rCe, rDi              \
    EOR rDo@>(64-1), ZR, rDo  \
                              \
    MOVD rCa, rDu             \
    EOR rCi, rDo              \
    EOR rDu@>(64-1), ZR, rDu  \
                              \
	/* Result b */            \
	MOVD _ba(iState), rBa     \
	MOVD _ge(iState), rBe     \
	EOR rCo, rDu              \
	MOVD _ki(iState), rBi     \
	MOVD _mo(iState), rBo     \
	MOVD _su(iState), rBu     \
    EOR rDe, rBe              \
    EOR rBe@>(64-44), ZR, rBe \
    EOR rDi, rBi              \
    EOR rDa, rBa              \
    EOR rBi@>(64-43), ZR, rBi \
                              \
	MOVD rBe, rCa             \
	MOVD rc, rT1              \
    ORR rBi, rCa              \
    EOR rBa, rT1              \
    EOR rT1, rCa              \
	MOVD rCa, _ba(oState)     \
                              \
	EOR rDu, rBu              \
	EOR rBu@>(64-14), ZR, rBu \
	MOVD rBa, rCu             \
	AND rBe, rCu              \
	EOR rBu, rCu              \
	MOVD rCu, _bu(oState)     \
                              \
	EOR rDo, rBo              \
	EOR rBo@>(64-21), ZR, rBo \
	MOVD rBo, rT1             \
	AND rBu, rT1              \
	EOR rBi, rT1              \
	MOVD rT1, _bi(oState)     \
	                          \
	MVN rBi, rBi              \
	ORR rBa, rBu              \
	ORR rBo, rBi              \
	EOR rBo, rBu              \
	EOR rBe, rBi              \
	MOVD rBu, _bo(oState)     \
	MOVD rBi, _be(oState)     \
	B_RBI_RCE;                \
	                          \
	/* Result g */            \
	MOVD _gu(iState), rBe     \
	EOR rDu, rBe              \
	MOVD _ka(iState), rBi     \
    EOR rBe@>(64-20), ZR, rBe \
	EOR rDa, rBi              \
	EOR rBi@>(64-3), ZR, rBi  \
	MOVD _bo(iState), rBa     \
	MOVD rBe, rT1             \
	ORR  rBi, rT1             \
	EOR rDo, rBa              \
	MOVD _me(iState), rBo     \
	MOVD _si(iState), rBu     \
    EOR rBa@>(64-28), ZR, rBa \
	EOR rBa, rT1              \
	MOVD rT1, _ga(oState)     \
	G_RT1_RCA;                \
	                          \
	EOR rDe, rBo              \
    EOR rBo@>(64-45), ZR, rBo \
	MOVD rBi, rT1             \
	AND rBo, rT1              \
	EOR rBe, rT1              \
	MOVD rT1, _ge(oState)     \
	G_RT1_RCE;                \
	                          \
	EOR rDi, rBu              \
    EOR rBu@>(64-61), ZR, rBu \
	MOVD rBu, rT1             \
	ORR  rBa, rT1             \
	EOR rBo, rT1              \
	MOVD rT1, _go(oState)     \
	                          \
	AND rBe, rBa              \
	EOR rBu, rBa              \
	MOVD rBa, _gu(oState)     \
    MVN rBu, rBu              \
	G_RBA_RCU;                \
	                          \
	ORR  rBu, rBo             \
	EOR rBi, rBo              \
	MOVD rBo, _gi(oState);    \
	                          \
	/* Result k */            \
	MOVD _be(iState), rBa     \
	MOVD _gi(iState), rBe     \
	MOVD _ko(iState), rBi     \
	MOVD _mu(iState), rBo     \
	MOVD _sa(iState), rBu     \
	EOR rDi, rBe              \
    EOR rBe@>(64-6), ZR, rBe  \
	EOR rDo, rBi              \
    EOR rBi@>(64-25), ZR, rBi \
	MOVD rBe, rT1             \
	ORR  rBi, rT1             \
	EOR rDe, rBa              \
    EOR rBa@>(64-1), ZR, rBa  \
	EOR rBa, rT1              \
	MOVD rT1, _ka(oState)     \
	K_RT1_RCA;                \
	                          \
	EOR rDu, rBo              \
    EOR rBo@>(64-8), ZR, rBo  \
	MOVD rBi, rT1             \
	AND rBo, rT1              \
	EOR rBe, rT1              \
	MOVD rT1, _ke(oState)     \
	K_RT1_RCE;                \
	                          \
	EOR rDa, rBu              \
    EOR rBu@>(64-18), ZR, rBu \
    MVN rBo, rBo              \
	MOVD rBo, rT1             \
	AND rBu, rT1              \
	EOR rBi, rT1              \
	MOVD rT1, _ki(oState)     \
	                          \
	MOVD rBu, rT1             \
	ORR  rBa, rT1             \
	EOR rBo, rT1              \
	MOVD rT1, _ko(oState)     \
	                          \
	AND rBe, rBa              \
	EOR rBu, rBa              \
	MOVD rBa, _ku(oState)     \
	K_RBA_RCU;                \
	                          \
	/* Result m */            \
	MOVD _ga(iState), rBe     \
	EOR rDa, rBe              \
	MOVD _ke(iState), rBi     \
    EOR rBe@>(64-36), ZR, rBe \
	EOR rDe, rBi              \
	MOVD _bu(iState), rBa     \
    EOR rBi@>(64-10), ZR, rBi \
	MOVD rBe, rT1             \
	MOVD _mi(iState), rBo     \
	AND  rBi, rT1             \
	EOR rDu, rBa              \
	MOVD _so(iState), rBu     \
    EOR rBa@>(64-27), ZR, rBa \
	EOR rBa, rT1              \
	MOVD rT1, _ma(oState)     \
	M_RT1_RCA;                \
	                          \
	EOR rDi, rBo              \
    EOR rBo@>(64-15), ZR, rBo \
	MOVD rBi, rT1             \
	ORR  rBo, rT1             \
	EOR rBe, rT1              \
	MOVD rT1, _me(oState)     \
	M_RT1_RCE;                \
	                          \
	EOR rDo, rBu              \
    EOR rBu@>(64-56), ZR, rBu \
    MVN rBo, rBo              \
	MOVD rBo, rT1             \
	ORR  rBu, rT1             \
	EOR rBi, rT1              \
	MOVD rT1, _mi(oState)     \
	                          \
	ORR  rBa, rBe             \
	EOR rBu, rBe              \
	MOVD rBe, _mu(oState)     \
	                          \
	AND rBa, rBu              \
	EOR rBo, rBu              \
	MOVD rBu, _mo(oState)     \
	M_RBE_RCU;                \
	                          \
	/* Result s */            \
	MOVD _bi(iState), rBa     \
	MOVD _go(iState), rBe     \
	MOVD _ku(iState), rBi     \
	EOR rDi, rBa              \
	MOVD _ma(iState), rBo     \
    EOR rBa@>(64-62), ZR, rBa \
	EOR rDo, rBe              \
	MOVD _se(iState), rBu     \
    EOR rBe@>(64-55), ZR, rBe \
	                          \
	EOR rDu, rBi              \
	MOVD rBa, rDu             \
	EOR rDe, rBu              \
    EOR rBu@>(64-2), ZR, rBu  \
	AND rBe, rDu              \
	EOR rBu, rDu              \
	MOVD rDu, _su(oState)     \
	                          \
    EOR rBi@>(64-39), ZR, rBi \
	S_RDU_RCU;                \
    MVN rBe, rBe              \
	EOR rDa, rBo              \
	MOVD rBe, rDa             \
	AND rBi, rDa              \
	EOR rBa, rDa              \
	MOVD rDa, _sa(oState)     \
	S_RDA_RCA;                \
	                          \
    EOR rBo@>(64-41), ZR, rBo \
	MOVD rBi, rDe             \
	ORR  rBo, rDe             \
	EOR rBe, rDe              \
	MOVD rDe, _se(oState)     \
	S_RDE_RCE;                \
	                          \
	MOVD rBo, rDi             \
	MOVD rBu, rDo             \
	AND rBu, rDi              \
	ORR  rBa, rDo             \
	EOR rBi, rDi              \
	EOR rBo, rDo              \
	MOVD rDi, _si(oState)     \
	MOVD rDo, _so(oState)     \

// func keccakF1600(state *[25]uint64)
TEXT ·keccakF1600(SB), 0, $208-8
	MOVD state+0(FP), rpState

	// Convert the user state into an internal state
	NOTD(rpState, _be, rTmp)
	NOTD(rpState, _bi, rTmp)
	NOTD(rpState, _go, rTmp)
	NOTD(rpState, _ki, rTmp)
	NOTD(rpState, _mi, rTmp)
	NOTD(rpState, _sa, rTmp)

	// Execute the KeccakF permutation
	MOVD _ba(rpState), rCa
	MOVD _be(rpState), rCe
	MOVD _bu(rpState), rCu

    XORDA(rpState, _ga, rTmp, rCa)
    XORDA(rpState, _ge, rTmp, rCe)
    XORDA(rpState, _gu, rTmp, rCu)

    XORDA(rpState, _ka, rTmp, rCa)
    XORDA(rpState, _ke, rTmp, rCe)
    XORDA(rpState, _ku, rTmp, rCu)

    XORDA(rpState, _ma, rTmp, rCa)
    XORDA(rpState, _me, rTmp, rCe)
    XORDA(rpState, _mu, rTmp, rCu)

    XORDA(rpState, _sa, rTmp, rCa)
    XORDA(rpState, _se, rTmp, rCe)
    MOVD _si(rpState), rDi
    MOVD _so(rpState), rDo
    XORDA(rpState, _su, rTmp, rCu)

	mKeccakRound(rpState, rpStack, $0x000000000000800a, MOVD_RBI_RCE, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBA_RCU, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBA_RCU, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBE_RCU, EOR_RDU_RCU, EOR_RDA_RCA, EOR_RDE_RCE)
	mKeccakRound(rpStack, rpState, $0x800000008000000a, MOVD_RBI_RCE, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBA_RCU, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBA_RCU, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBE_RCU, EOR_RDU_RCU, EOR_RDA_RCA, EOR_RDE_RCE)
	mKeccakRound(rpState, rpStack, $0x8000000080008081, MOVD_RBI_RCE, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBA_RCU, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBA_RCU, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBE_RCU, EOR_RDU_RCU, EOR_RDA_RCA, EOR_RDE_RCE)
	mKeccakRound(rpStack, rpState, $0x8000000000008080, MOVD_RBI_RCE, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBA_RCU, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBA_RCU, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBE_RCU, EOR_RDU_RCU, EOR_RDA_RCA, EOR_RDE_RCE)
	mKeccakRound(rpState, rpStack, $0x0000000080000001, MOVD_RBI_RCE, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBA_RCU, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBA_RCU, EOR_RT1_RCA, EOR_RT1_RCE, EOR_RBE_RCU, EOR_RDU_RCU, EOR_RDA_RCA, EOR_RDE_RCE)
	mKeccakRound(rpStack, rpState, $0x8000000080008008, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP)

	// Revert the internal state to the user state
	NOTD(rpState, _be, rTmp)
	NOTD(rpState, _bi, rTmp)
	NOTD(rpState, _go, rTmp)
	NOTD(rpState, _ki, rTmp)
	NOTD(rpState, _mi, rTmp)
	NOTD(rpState, _sa, rTmp)

    RET
