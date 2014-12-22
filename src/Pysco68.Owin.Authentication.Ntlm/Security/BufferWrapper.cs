namespace Pysco68.Owin.Authentication.Ntlm.Security
{
    using System;

    struct BufferWrapper
    {
        public byte[] Buffer;
        public SecurityBufferType BufferType;

        public BufferWrapper(byte[] buffer, SecurityBufferType bufferType)
        {
            if (buffer == null || buffer.Length == 0)
            {
                throw new ArgumentException("buffer cannot be null or 0 length");
            }

            Buffer = buffer;
            BufferType = bufferType;
        }
    };
}
