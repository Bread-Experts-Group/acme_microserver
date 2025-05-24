package org.bread_experts_group.acme_microserver

enum class P12FileLinkOption(val description: String) {
	NO_LINK("No file is created"),
	FS_SOFT_LINK("A file-system supported symlink (soft link, pointer) to the latest P12 will be created"),
	FS_HARD_LINK("A file-system supported hard link (copy with backing) to the latest P12 will be created"),
	COPY("The latest P12 will be copied directly")
}