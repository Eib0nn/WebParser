using System;
using System.Runtime.InteropServices;

class ParserGlue
{
    [DllImport("libengine.so", EntryPoint = "parse_file", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr parse_file(string filename);

    [DllImport("libengine.so", EntryPoint = "free_parser_output", CallingConvention = CallingConvention.Cdecl)]
    public static extern void free_parser_output(IntPtr p);

    public static string RunParser(string path)
    {
        IntPtr p = parse_file(path);
        if (p == IntPtr.Zero)
            throw new Exception("Parser returned NULL");

        string result = Marshal.PtrToStringAnsi(p) ?? string.Empty;
        free_parser_output(p);
        return result;
    }
}