# shrike examples

One recipe per common task. Copy the command, substitute your
binary, read the output.

## 1. Everything in /bin/ls
```bash
shrike /bin/ls
```

## 2. Only pops, deduplicated, no null/newline in address
```bash
shrike /bin/bash --filter 'pop ' --unique \
    --bad-bytes 0x00,0x0a
```

## 3. Register control map as a Python dict
```bash
shrike --reg-index-python /bin/bash > regs.py
```

## 4. Minimal execve chain
```bash
shrike /bin/bash /lib/x86_64-linux-gnu/libc.so.6 \
    --recipe 'rdi=*; rsi=*; rdx=*; rax=59; syscall' \
    --format pwntools > exploit.py
```

## 5. SARIF for GitHub Code Scanning
```bash
shrike --sarif --sarif-cap 2000 dist/*.so > shrike.sarif
```

## 6. Supply-chain diff between libc versions
```bash
shrike --diff /old/libc.so.6 /new/libc.so.6 | head
```

## 7. Multi-binary unique gadget universe
```bash
shrike --unique --canonical --intersect \
    dist/my-service /lib/x86_64-linux-gnu/libc.so.6
```

## 8. Scan a PE .text extracted with objcopy
```bash
objcopy -O binary --only-section=.text foo.exe foo.text
shrike --raw --raw-arch x86_64 --raw-base 0x401000 foo.text
```

## 9. CET posture audit
```bash
shrike --cet-posture --wx-check dist/*.so
```

## 10. ROPecker-style density heatmap
```bash
shrike --density /bin/bash | less
```
