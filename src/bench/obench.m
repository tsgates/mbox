## PURPOSE:
## This program serves as a benchmark, running a long series of
## tests ranging from "small" (80K) to "large" (70MB) matrices.
##
## To run simply type:
##
##    octave -q obench.m
##
## please send results to: marco@reimeika.ca. If you run this benchmark
## off a Quantian Linux 0.7.9.1 live DVD it qualifies as a "standard system".
## You can obtain the ISO image from:
##
##    http://quantian.fhcrc.org/
##
## Please make note of this if submitting results.
##
## Version: 30 Jan 2006: first release
## Version: 04 Feb 2006: check matrix condition number (via makematrix())
##                       use proper end for statements (e.g. endfor)
##                       smarter system info gathering (untested for windows).
## Version: 06 Feb 2006: under Windows the OS is actually "cygwin".
## Version: 07 Feb 2006: mention "standard system".
## Version: 09 Feb 2006: fixed small bug in integration status check.


function progress(title, cycle, total)
  home; disp(title), disp("Loop"), disp(cycle), disp("of"), disp(total)
endfunction

function r = makematrix(msize, iscpx, condn)
  while 1
    if iscpx
      r = rand(msize) + i*rand(msize);
    else
      r = rand(msize);
    endif
    if cond(r) <= condn break; endif
  endwhile
endfunction

results.total = 0;

nested = "(1/5) Nested FOR loops              ";
loops = 40;
clc; t0 = time;
for ii = 1:loops
  progress(nested, ii, loops);
  for jj = 1:loops
    for kk = 1:loops
      for ll = 1:loops
	for mm = 1:loops
	  A = 0;
	  A = 1;
	endfor
      endfor
    endfor
  endfor
endfor
results.nested = time - t0;
results.total += results.nested;

integration = "(2/5) Integration/function calls    ";
loops = 100; p = 1000;
clc; t0 = time;
function r = f(x)
  global y;
  r = cos(x**2)*(x**2*(1-x)+sin(y/exp(x))) + x*sin(x**3);
endfunction
function [r,s] = F(uplim)
  [r,s] = quad("f", -1.3, uplim);
endfunction
sf = 0; global y;
y_vec = linspace(-5, 5, p);
for ii = 1:loops
  progress(integration, ii, loops);
  for y = y_vec
    [r,s] = F(ii/loops);
    sf+=s;
  endfor
endfor
results.integration = time - t0;
results.intstat = sf;
results.total += results.integration;

fast = "(3/5) Random matrix/FFT calculation ";
loops = 200;
clc; t0 = time;
for ii = 1:loops
  progress(fast, ii, loops);
  fft(rand(3000));
endfor
results.fast = time - t0;
results.total += results.fast;

simple = "(4/5) Simple matrix operations      ";
loops = 20; s1 = 100; s2 = 1000;
disp("Thinking... please wait a moment...")
a = makematrix(s1, 1, 1000); b = makematrix(s1, 1, 1000);
A = makematrix(s2, 1, 100*1000); B = makematrix(s2, 1, 100*1000);
clc; t0 = time;
for ii = 1:loops
  progress(simple, ii, loops);
  A+ii*B; A-ii*B; A.*ii*B; A*ii*B;
  log(ii*A); gamma(real(ii*A)); sort(imag(ii*B));
  for jj = 1:loops
    a+jj*b; a-jj*b; a.*jj*b; a*jj*b;
    log((jj+ii)*a); gamma(real((jj+ii)*a)); sort(imag((jj+ii)*b));
  endfor
endfor
results.simple = time - t0;
results.total += results.simple;

complex = "(5/5) Complex matrix operations     ";
loops = 10; s1 = 100; s2 = 800;
disp("Thinking... please wait a moment...")
a = makematrix(s1, 1, 1000);
A = makematrix(s2, 1, 30*1000);
clc; t0 = time;
for ii = 1:loops
  progress(complex, ii, loops);
  inv(ii*A); lu(ii*A); [x,y] = eig(ii*A);
  for jj = 1:loops
    inv((jj+ii)*a); lu((jj+ii)*a); [x,y] = eig((jj+ii)*a);
  endfor
endfor
results.complex = time - t0;
results.total += results.complex;

clc
disp("RESULTS AND SYSTEM INFO:")
disp("")
printf("%s: %14.2fs\n", nested, results.nested);
printf("%s: %14.2fs (status should be 0: %1i)\n", integration, results.integration, results.intstat);
printf("%s: %14.2fs\n", fast, results.fast);
printf("%s: %14.2fs\n", simple, results.simple);
printf("%s: %14.2fs\n", complex, results.complex);
printf("+ Total time                        : %14.2fs\n", results.total);
disp("")
OCTAVE_VERSION
disp(computer())
disp("obench version 09 Feb 2006")
if index(tolower(computer()), "linux")
  system("uname -s -r");
  system("free -o | head -2");
  system("cat /proc/cpuinfo | egrep '(processor|model name|cpu MHz|cache size|bogomips)'");
elseif index(tolower(computer()), "cygwin")
  system("systeminfo");
else
  disp("Unknown OS, please obtain hardware specs manually (and/or send me a patch ;)")
endif
disp("")
disp("\nPlease send output to")
disp("marco@reimeika.ca (http://www.reimeika.ca/marco/obench). Thanks!")
