(load "chall.lisp")

(sb-ext:save-lisp-and-die "chall"
			  :executable t
			  :toplevel #'main)
