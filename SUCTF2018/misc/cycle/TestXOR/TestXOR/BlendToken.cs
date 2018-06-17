using System;

namespace TestXOR
{
	/// <summary>
	/// BlendToken 的摘要说明。
	/// </summary>
	public class BlendToken
	{
		public BlendToken(byte Alpha, byte Beta)
		{
            this.Alpha = Alpha;
            this.Beta = Beta;
            this.Blend = (byte) (Alpha ^ Beta);
		}

        public byte Blend;
        public byte Alpha;
        public byte Beta;
	}
}
