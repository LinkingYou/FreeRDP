# get all project files
file(GLOB_RECURSE ALL_SOURCE_FILES *.cpp *.c *.h *.m *.java)

find_program(CLANG_FORMAT
	NAMES
	clang-format-6.0)

if (NOT CLANG_FORMAT)
	message(WARNING "clang-format-6.0 not found in path! code format target not available.")
else()
	add_custom_target(
		clangformat
		COMMAND ${CLANG_FORMAT}
		-style=file
		-i
		${ALL_SOURCE_FILES}
	)
endif()
