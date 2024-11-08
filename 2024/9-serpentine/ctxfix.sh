#!/bin/bash

# sed -i -E 's|.+\[[a-z0-9]{2,4}\+28h\]|<|g>' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+34h\]|<mxcsr>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+78h\]|<rax>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+90h\]|<rbx>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+80h\]|<rcx>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+88h\]|<rdx>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+0B0h\]|<rdi>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+0A8h\]|<rsi>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+0A0h\]|<rbp>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+0B8h\]|<r8>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+0C0h\]|<r9>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+0C8h\]|<r10>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+0D0h\]|<r11>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+0D8h\]|<r12>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+0E0h\]|<r13>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+0E8h\]|<r14>|g' "$1"
sed -i -E 's|\[[a-z0-9]{2,4}\+0F0h\]|<r15>|g' "$1"