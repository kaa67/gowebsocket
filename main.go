package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
)

func main() {
	http.HandleFunc("/websocket", wsHandle)
	http.ListenAndServe(":8000", nil)
}

func wsHandle(w http.ResponseWriter, r *http.Request) {
	// проверяем заголовки
	if r.Header.Get("Upgrade") != "websocket" {
		return
	}
	if r.Header.Get("Connection") != "Upgrade" {
		return
	}
	k := r.Header.Get("Sec-Websocket-Key")
	if k == "" {
		return
	}

	// вычисляем ответ
	sum := k + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	hash := sha1.Sum([]byte(sum))
	str := base64.StdEncoding.EncodeToString(hash[:])

	// Берем под контроль соединение https://pkg.go.dev/net/http#Hijacker
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	// формируем ответ
	bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	bufrw.WriteString("Upgrade: websocket\r\n")
	bufrw.WriteString("Connection: Upgrade\r\n")
	bufrw.WriteString("Sec-Websocket-Accept: " + str + "\r\n\r\n")
	bufrw.Flush()

	// выводим все, что пришло от клиента
	var message []byte

	for {
		// заголовок состоит из 2 — 14 байт
		buf := make([]byte, 2, 12)
		// читаем первые 2 байта
		_, err := bufrw.Read(buf)
		if err != nil {
			return
		}

		finBit := buf[0] >> 7  // фрагментированное ли сообщение
		opCode := buf[0] & 0xf // опкод 0...15
		maskBit := buf[1] >> 7 // замаскированы ли данные

		// оставшийся размер заголовка
		extra := 0
		if maskBit == 1 {
			extra += 4 // +4 байта маскировочный ключ
		}

		size := uint64(buf[1] & 0x7f) // 0111 1111

		if size == 126 {
			extra += 2 // +2 байта размер данных
		} else if size == 127 {
			extra += 8 // +8 байт размер данных
		}

		if extra > 0 {
			// читаем остаток заголовка extra <= 12
			buf = buf[:extra]
			_, err = bufrw.Read(buf)
			if err != nil {
				return
			}

			if size == 126 {
				size = uint64(binary.BigEndian.Uint16(buf[:2]))
				buf = buf[2:] // подвинем начало буфера на 2 байта
			} else if size == 127 {
				size = uint64(binary.BigEndian.Uint64(buf[:8]))
				buf = buf[8:] // подвинем начало буфера на 8 байт
			}
		}

		// маскировочный ключ
		var mask []byte
		if maskBit == 1 {
			// остаток заголовка, последние 4 байта
			mask = buf
		}

		// данные фрейма
		payload := make([]byte, int(size))
		// читаем полностью и ровно size байт
		_, err = io.ReadFull(bufrw, payload)
		if err != nil {
			return
		}

		// размаскировываем данные с помощью XOR
		if maskBit == 1 {
			for i := 0; i < len(payload); i++ {
				payload[i] ^= mask[i%4]
			}
		}

		// складываем фрагменты сообщения
		message = append(message, payload...)

		if opCode == 8 { // фрейм закрытия
			return
		} else if finBit == 1 { // конец сообщения
			fmt.Println(string(message))

			bufrw.Write(buf)
			bufrw.Flush()

			message = message[:0]
		}
	}
}
