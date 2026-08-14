# SKILL: VM & Bytecode Reverse Engineering — Expert Analysis Playbook: detailed technique reference

<!-- zhiyugo:resource:start -->
> ZhiyuGo reference material only. Inspect it explicitly through catalog resource tooling when the main Skill names this file; examples do not grant tools, authorization, or evidence.
<!-- zhiyugo:resource:end -->

<!-- zhiyugo:toc:start -->
## Contents

- [3. COMMON VM PATTERNS IN CTF](#3-common-vm-patterns-in-ctf)
- [4. MAZE CHALLENGES](#4-maze-challenges)
- [5. REAL-WORLD VM PROTECTORS](#5-real-world-vm-protectors)
- [6. TOOLS](#6-tools)
- [7. DECISION TREE](#7-decision-tree)
- [8. CTF SOLVING WORKFLOW](#8-ctf-solving-workflow)
<!-- zhiyugo:toc:end -->

## 3. COMMON VM PATTERNS IN CTF

### 3.1 Stack-Based VM

Operations work on a stack (like JVM or Python bytecode).

| Opcode | Operation | Stack Effect |
|---|---|---|
| PUSH imm | Push immediate value | [...] → [..., imm] |
| POP | Discard top | [..., a] → [...] |
| ADD | Add top two | [..., a, b] → [..., a+b] |
| SUB | Subtract | [..., a, b] → [..., a-b] |
| MUL | Multiply | [..., a, b] → [..., a*b] |
| XOR | Bitwise XOR | [..., a, b] → [..., a^b] |
| CMP | Compare | [..., a, b] → [..., (a==b)] |
| JMP addr | Unconditional jump | no change |
| JZ addr | Jump if top is zero | [..., a] → [...] |
| PRINT | Output top as char | [..., a] → [...] |
| READ | Read char to stack | [...] → [..., input] |
| HALT | Stop execution | - |

### 3.2 Register-Based VM

Operations use register indices (like x86, ARM).

| Opcode | Format | Operation |
|---|---|---|
| MOV r, imm | `0x01 RR II II` | reg[R] = imm16 |
| MOV r1, r2 | `0x02 R1 R2` | reg[R1] = reg[R2] |
| ADD r1, r2 | `0x03 R1 R2` | reg[R1] += reg[R2] |
| SUB r1, r2 | `0x04 R1 R2` | reg[R1] -= reg[R2] |
| XOR r1, r2 | `0x05 R1 R2` | reg[R1] ^= reg[R2] |
| CMP r1, r2 | `0x06 R1 R2` | flags = compare(r1, r2) |
| JMP addr | `0x07 AA AA` | pc = addr |
| JE addr | `0x08 AA AA` | if equal: pc = addr |
| LOAD r, [addr] | `0x09 RR AA` | reg[R] = mem[addr] |
| STORE [addr], r | `0x0A AA RR` | mem[addr] = reg[R] |
| SYSCALL | `0x0B` | I/O operation based on reg[0] |
| HALT | `0xFF` | stop |

### 3.3 Brainfuck-like / Esoteric VMs

| BF Command | VM Equivalent | Description |
|---|---|---|
| `>` | INC ptr | Move data pointer right |
| `<` | DEC ptr | Move data pointer left |
| `+` | INC [ptr] | Increment byte at pointer |
| `-` | DEC [ptr] | Decrement byte at pointer |
| `.` | OUTPUT [ptr] | Output byte at pointer |
| `,` | INPUT [ptr] | Input byte to pointer |
| `[` | JZ forward | Jump past `]` if byte is zero |
| `]` | JNZ back | Jump back to `[` if byte is nonzero |

---

## 4. MAZE CHALLENGES

### 4.1 Identification

- Binary reads directional input (WASD, arrow keys, UDLR)
- 2D array in data section (walls, paths, start, end)
- Position tracking with x,y coordinates
- Win condition at specific coordinates

### 4.2 Map Extraction

```python
# Extract maze grid from binary data section
MAZE_ADDR = 0x601060
WIDTH = 20
HEIGHT = 15

# From binary dump:
maze = []
for row in range(HEIGHT):
    line = ""
    for col in range(WIDTH):
        cell = bytecode[MAZE_ADDR + row * WIDTH + col - base_addr]
        if cell == 0: line += "."    # path
        elif cell == 1: line += "#"  # wall
        elif cell == 2: line += "S"  # start
        elif cell == 3: line += "E"  # end
        else: line += "?"
    maze.append(line)
    print(line)
```

### 4.3 Automated Solving

```python
from collections import deque

def solve_maze(maze, start, end):
    """BFS solver returns direction string."""
    rows, cols = len(maze), len(maze[0])
    directions = {'U': (-1, 0), 'D': (1, 0), 'L': (0, -1), 'R': (0, 1)}
    queue = deque([(start, "")])
    visited = {start}

    while queue:
        (r, c), path = queue.popleft()
        if (r, c) == end:
            return path

        for name, (dr, dc) in directions.items():
            nr, nc = r + dr, c + dc
            if (0 <= nr < rows and 0 <= nc < cols and
                maze[nr][nc] != '#' and (nr, nc) not in visited):
                visited.add((nr, nc))
                queue.append(((nr, nc), path + name))

    return None

# Find start and end positions
for r, row in enumerate(maze):
    for c, cell in enumerate(row):
        if cell == 'S': start = (r, c)
        if cell == 'E': end = (r, c)

solution = solve_maze(maze, start, end)
print(f"Path: {solution}")
```

### 4.4 Direction Encoding

Different challenges encode directions differently:

| Encoding | Up | Down | Left | Right |
|---|---|---|---|---|
| WASD | W | S | A | D |
| UDLR | U | D | L | R |
| Arrow keys | ↑ (0x48) | ↓ (0x50) | ← (0x4B) | → (0x4D) |
| Numbers | 1 | 2 | 3 | 4 |
| Hex opcodes | 0x01 | 0x02 | 0x03 | 0x04 |

---

## 5. REAL-WORLD VM PROTECTORS

### 5.1 VMProtect Analysis Approach

```
1. Find VM entry: search for pushad/pushfd sequence
2. Identify VM context structure (registers, flags, bytecode pointer)
3. Locate handler table (often obfuscated with opaque predicates)
4. For each handler:
   a. Remove junk code / opaque predicates
   b. Identify the core operation
   c. Document handler semantics
5. Trace bytecode execution (instruction-level trace)
6. Reconstruct original code from trace
```

### 5.2 Tigress Obfuscator

Academic VM obfuscator with configurable protection layers.

| Feature | Approach |
|---|---|
| Single-dispatch VM | Standard handler extraction |
| Split handlers | Handlers spread across multiple functions |
| Nested VMs | Outer VM handler invokes inner VM |
| Encrypted bytecode | Dynamic decryption before each fetch |
| Polymorphic handlers | Different code for same operation on each build |

### 5.3 Common VM Protector Patterns

| Protector | Dispatcher Style | Difficulty |
|---|---|---|
| VMProtect | Table + opaque predicates | High |
| Themida (Code Virtualizer) | CISC-like, large handler set | High |
| Tigress | Configurable, academic | Medium-High |
| Custom CTF VM | Simple switch | Low-Medium |
| Movfuscator | All-mov computation | Medium |

---

## 6. TOOLS

| Tool | Purpose | Usage |
|---|---|---|
| IDA Pro | Identify dispatcher, reverse handlers | F5 decompile, xref analysis |
| Ghidra | Free alternative with Sleigh processor modules | Write custom processor for VM ISA |
| angr | Symbolic execution through VM | Treat entire VM as constraint system |
| Pin / DynamoRIO | Dynamic instrumentation for tracing | Record opcode handler execution sequence |
| REVEN | Full-system trace recording | Replay and analyze VM execution |
| Unicorn | Emulate VM execution | Fast handler emulation |
| Miasm | IR-based analysis | Lift VM handlers to IR for analysis |
| Custom Python | Write disassembler/decompiler | Per-challenge custom tooling |

### Ghidra Sleigh Processor Module

For recurring VM architectures, write a Sleigh processor specification:

```
define space ram      type=ram_space      size=2  default;
define space register type=register_space  size=1;

define register offset=0 size=1 [ R0 R1 R2 R3 FLAGS PC SP ];

define token opcode(8)
    op = (0,7)
;

:NOP    is op=0x00 { }
:PUSH   imm is op=0x01; imm { SP = SP - 1; *[ram]:1 SP = imm; }
:POP    is op=0x02 { SP = SP + 1; }
:ADD    is op=0x03 { local a = *[ram]:1 (SP+1); *[ram]:1 (SP+1) = a + *[ram]:1 SP; SP = SP + 1; }
```

---

## 7. DECISION TREE

```
Binary contains custom bytecode interpreter?
│
├─ Can you identify the dispatcher?
│  ├─ Yes (switch/table/if-chain)
│  │  ├─ Few opcodes (< 20) → Simple CTF VM
│  │  │  ├─ Stack-based → map push/pop/arithmetic ops
│  │  │  ├─ Register-based → map mov/add/cmp ops
│  │  │  └─ Write disassembler → analyze program → solve
│  │  │
│  │  └─ Many opcodes (50+) → Commercial protector
│  │     ├─ Known protector → use specific deprotection tools
│  │     └─ Custom → trace execution, pattern-match handlers
│  │
│  └─ No clear dispatcher
│     ├─ All-mov instructions → movfuscator
│     ├─ Encrypted bytecode → find decryption, dump after decode
│     └─ Split/distributed handlers → trace execution to find them
│
├─ Is it a maze challenge?
│  ├─ Extract grid from data section
│  ├─ Identify direction encoding
│  ├─ BFS/DFS to find shortest path
│  └─ Convert path to expected input format
│
├─ Is there input validation in VM?
│  ├─ Small input space → brute-force via Unicorn emulation
│  ├─ Known format → constrained angr solve
│  └─ Complex check → write disassembler, analyze check logic
│
└─ Multiple VM layers (VM in VM)?
   ├─ Analyze outer VM first
   ├─ Extract inner bytecode
   ├─ Repeat analysis for inner VM
   └─ Consider: symbolic execution may handle nested VMs directly
```

---

## 8. CTF SOLVING WORKFLOW

```
1. Run the binary — understand I/O behavior
   └─ What input does it expect? What output on success/failure?

2. Open in IDA/Ghidra — find the main loop
   └─ Look for while/for loop with switch or indirect jump

3. Identify VM components:
   ├─ Bytecode location (where is the program data?)
   ├─ PC/IP variable (how is current position tracked?)
   ├─ Registers/stack (where is VM state stored?)
   └─ I/O handlers (which opcodes read input / write output?)

4. Map all opcodes (create the ISA specification)
   └─ For each case/handler: opcode number, operation, operands

5. Write disassembler in Python
   └─ Output readable assembly for the bytecode

6. Analyze the disassembled program:
   ├─ Find input reading
   ├─ Trace transformations applied to input
   ├─ Find comparison against expected values
   └─ Reverse the transformation to find valid input

7. Solve:
   ├─ If simple transforms (XOR, ADD) → reverse manually
   ├─ If complex → feed to Z3 as constraints
   └─ If maze → extract grid, run pathfinding
```
