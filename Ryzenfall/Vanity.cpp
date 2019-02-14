//
// @depletionmode 2019
//

#include <Windows.h>

EXTERN_C_START

const char* vanity = R"(
  _____                     ______    _ _            
 |  __ \                   |  ____|  | | |           
 | |__) |   _ _______ _ __ | |__ __ _| | | ___ _ __  
 |  _  / | | |_  / _ \ '_ \|  __/ _` | | |/ _ \ '_ \ 
 | | \ \ |_| |/ /  __/ | | | | | (_| | | |  __/ | | |
 |_|  \_\__, /___\___|_| |_|_|  \__,_|_|_|\___|_| |_|
         __/ |                                       
        |___/                                        

 Ryzenfall exploitation PoC by @depletionmode

 With thanks to:

   @idolion_, @uri_farkas           - Ryzenfall vulnerability
   @aionescu                        - WDF code
   @HackingThings, @WithinRafael    - Platform tests
   @msuiche                         - Hummus in Zone 3

 NOTE:

   All information used to reproduce Ryzenfall is readily available from a mix 
   of the CTS presentation at BlueHatIL '19 and minimal RE of UEFI fimrware.
   The public component of this PoC includes a read-what-where primitive only.
   Expansion of primitives is left as an exercise to the reader.

)";

EXTERN_C_END
