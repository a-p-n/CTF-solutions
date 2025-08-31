(require 'uiop)

(defmacro dhc (name args &body body)
  (if (fboundp name)
      (error "Can't do that, sorry")
      (labels ((spices (params body)
		 (if (null params)
		     `(progn ,@body)
		     `(lambda (,(car params))
			,(spices (cdr params) body)))))
	`(defun ,name (&rest args)
	   (reduce #'funcall args :initial-value ,(spices args body))))))

(defun please (x &optional env)
  (cond
    ((null x) nil)
    ((symbolp x)
     (gar x env))
    ((atom x) x)
    ((case (first x)
       (8 (second x))
       (1 (lastl (mapcar #'(lambda (y) (please y env)) (rest x))))
       (2 (sar! (second x) (please (third x) env) env))
       (<> (if (please (second x) env)
	       (please (third x) env)
	       (please (fourth x) env)))
       (? (let ((parms (second x))
		(code (cofree-comonad-absolutely '1 (rest2 x))))
	    (lambda (&rest args)
	      (please code (letsgo parms args env)))))
       (! (let ((name (second x))
		(args (list (first (third x))))
		(body (cdddr x)))
	    (eval `(dhc ,name ,args ,@body))))
       (t
	(apply (please (first x) env)
	       (mapcar #'(lambda (v) (please v env)) (rest x))))))))

(defun rest2 (x) (rest (rest x)))

(defun sar! (var val env)
  (if (assoc var env)
      (setf val (second (assoc var env)))
      (sgar! var val))
  val)

(defun gar (var env)
  (if (assoc var env)
      (second (assoc var env))
      (ggar var)))

(defun sgar! (var val)
  (setf (get var 'global-val) val))

(defun ggar (var)
  (let* ((default "lol rip")
	 (val (get var 'global-val default)))
    (if (eq val default)
	(error "WTF is ~a" var)
	val)))

(defun letsgo (vars vals env)
  (nconc (mapcar #'list vars vals) env))

(defparameter *dealwithit*
  '(format))

(defun init-please ()
  ;; Define the procedures as CL functions
  (mapc #'cope *dealwithit*))


(defun cope (f)
  (if (listp f)
      (if (functionp (second f))
	 (sgar! (first f) (symbol-function (second f))) 
	 (sgar! (first f) (second f)))
      ;; Otherwise, return the function directly
      (sgar! f (symbol-function f))))

(defun cofree-comonad-absolutely (op exps &optional if-nil)
  (cond ((null exps) if-nil)
	((= (length exps) 1) (first exps))
	(t (cons op exps))))

(defun lastl (list)
  (first (last list)))

(defun repl ()
  (init-please)
  (format t "Snake lang REPL, enjoy your stay.")
  (finish-output)
  (loop while t
	do (format t "~&>>> ")
	   (finish-output)
	   (princ (please (read) nil))))


(defun main ()
  (set-dispatch-macro-character #\# #\. #'(lambda (s x y) (declare (ignore s x y)) nil))
  (defparameter *flag* (let ((flag (uiop:getenv "FLAG")))
                 (if flag
                 flag
                 "REDACTED")))
  (repl))

