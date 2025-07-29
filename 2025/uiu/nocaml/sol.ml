let () =
  let ic = Stdlib.open_in_bin "./flag.txt" in
  let len = Stdlib.in_channel_length ic in
  let buf = Stdlib.really_input_string ic len in
  Stdlib.print_string buf;
  Stdlib.close_in ic

