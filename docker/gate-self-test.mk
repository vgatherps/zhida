# Fixtures for `make docker-gate-self-test`, run as `make -f` in the Zhida
# container. Each goal is one stuck step followed by another, like `make test`.
# hang: a step with no bound of its own never ends.
# term: a step bounded like the real ones runs until the self-test, once it has
# seen `term-step: started`, sends SIGTERM to the container (`docker kill`). The
# step is one shell line, so its timeout (own process group) is make's
# grandchild: without --init, make as PID 1 kills the shell, the TERM it
# re-raises on itself is dropped, and it waits on the orphaned timeout.
.NOTPARALLEL:
.PHONY: hang term hang-step term-step after

hang: hang-step after
term: term-step after

hang-step:
	sleep 1000

term-step:
	@echo 'term-step: started'; timeout --kill-after=10 600 sleep 1000

after:
	@echo 'after: ran; the stuck step did not end the run'
