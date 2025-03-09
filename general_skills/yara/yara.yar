//made by mel

//packed binary should work with unpacked
rule packed {
	strings:
		//banner taken from strings
		$banner = "Welcome to the YaraRules0x100 challenge!" wide ascii

		//suspicious api call for malicious binaries
		$api_2 = "OpenProcessToken" nocase wide ascii

		//pico icon taken from ghidra
		$icon = {28 00 00 00 30 00 00 00 60 00 00 00 01 00 20 00 00 00 00 00 00 24 00 00 c3 0e 00 00 c3 0e 00 00 00 00 00 00 00 00}

	condition:
		//make sure its an exe
		uint16(0) == 0x5A4D and (
			//banners/pico icon
			($banner or $icon) and
			
			//check for suspicious api calls
			all of ($api*)
		)
}