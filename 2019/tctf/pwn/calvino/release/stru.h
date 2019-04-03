typedef struct {
    int key;
    int shift;
    int step;
    int orig_size;
    int size;
    int cur_idx;
    BYTE *buffer;
} perm_state_T;