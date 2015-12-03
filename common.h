#define UNUSED(x) (void)(x)

typedef void (*thread_fn)(void *);

int spawn(thread_fn fn, void *payload);
