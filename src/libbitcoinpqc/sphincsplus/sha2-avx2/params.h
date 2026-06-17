#define str(s) #s
#define xstr(s) str(s)

#include xstr(params/params-PARAMS.h)

#ifndef SPX_FORS_SIG_TREES
#define SPX_FORS_SIG_TREES SPX_FORS_TREES
#endif
