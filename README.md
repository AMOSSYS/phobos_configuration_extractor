# phobos_configuration_extractor
For mor information about this program, read ALMOND/AMOSSYS Article about 8Base:
<FIXME>

# Prerequisites
For now, this script is not independent and requires IDA Pro V 7.4+ to execute a Python 3 script. This one has been tested and used on IDA Pro 8.3.
It is necessary to rename an address in IDB before executing the script. This one can be found easily at the beginning of the main function.
This address represents the header of the payload containing the configuration. This address must be renamed « payload_header ». If another name is used, it will be essential to modify the script to consider the new name. 

# Use of the extractor 
The extractor can be used as a Python scripting on IDA Pro. The option is in « File > Script file… » or by using the shortcut by default Alt+F7.
The configuration will then be extracted and displayed in the ”Output” window.
