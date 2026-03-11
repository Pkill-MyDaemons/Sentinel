#ifndef HXCPP_CONFIG_INCLUDED
#define HXCPP_CONFIG_INCLUDED

#if !defined(_FILE_OFFSET_BITS) && !defined(NO__FILE_OFFSET_BITS)
#define _FILE_OFFSET_BITS 64
#endif

#if !defined(wxDEBUG_LEVEL) && !defined(NO_wxDEBUG_LEVEL)
#define wxDEBUG_LEVEL 0
#endif

#if !defined(WXUSINGDLL) && !defined(NO_WXUSINGDLL)
#define WXUSINGDLL 
#endif

#if !defined(__WXMAC__) && !defined(NO___WXMAC__)
#define __WXMAC__ 
#endif

#if !defined(__WXOSX__) && !defined(NO___WXOSX__)
#define __WXOSX__ 
#endif

#if !defined(__WXOSX_COCOA__) && !defined(NO___WXOSX_COCOA__)
#define __WXOSX_COCOA__ 
#endif

#if !defined(wxUSE_GRAPHICS_CONTEXT) && !defined(NO_wxUSE_GRAPHICS_CONTEXT)
#define wxUSE_GRAPHICS_CONTEXT 
#endif

#if !defined(HX_MACOS) && !defined(NO_HX_MACOS)
#define HX_MACOS 
#endif

#if !defined(HXCPP_ARM64) && !defined(NO_HXCPP_ARM64)
#define HXCPP_ARM64 
#endif

#if !defined(HXCPP_M64) && !defined(NO_HXCPP_M64)
#define HXCPP_M64 
#endif

#if !defined(HXCPP_VISIT_ALLOCS) && !defined(NO_HXCPP_VISIT_ALLOCS)
#define HXCPP_VISIT_ALLOCS 
#endif

#if !defined(HX_SMART_STRINGS) && !defined(NO_HX_SMART_STRINGS)
#define HX_SMART_STRINGS 
#endif

#if !defined(HXCPP_API_LEVEL) && !defined(NO_HXCPP_API_LEVEL)
#define HXCPP_API_LEVEL 430
#endif

#include <hxcpp.h>

#endif
