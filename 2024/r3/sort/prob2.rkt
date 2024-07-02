#!/usr/bin/racket
#lang racket
(require "run_rkt.zo")
(require net/base64)
(require racket/random)
(display "Your Stack Machine code: ")
(define code (bytes->list (base64-decode (read-bytes-line))))
(if (<= (length code) 5000) (void) (error "Code too long"))
(for ([n 10]) 
(begin
(define test-input (map (lambda (x) (random 32 127)) (build-list (random 20 30) values)))
(define test-output (list->bytes (sort test-input <)))
(define test-input-n (for/fold ([acc 0]) ([i test-input]) (+ (arithmetic-shift acc 8) i)))
(define test-output-n (for/fold ([acc 0]) ([i test-output]) (+ (arithmetic-shift acc 8) i)))
(if (= (car (run code (list test-input-n))) test-output-n) #t (error "Wrong"))
))
(display (port->string (open-input-file "flag.txt")))