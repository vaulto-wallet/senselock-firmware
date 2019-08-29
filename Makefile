.PHONY: clean All

All:
	@echo "----------Building project:[ bitlock - Debug ]----------"
	@cd "bitlock" && "$(MAKE)" -f  "bitlock.mk" && "$(MAKE)" -f  "bitlock.mk" PostBuild
clean:
	@echo "----------Cleaning project:[ bitlock - Debug ]----------"
	@cd "bitlock" && "$(MAKE)" -f  "bitlock.mk" clean
