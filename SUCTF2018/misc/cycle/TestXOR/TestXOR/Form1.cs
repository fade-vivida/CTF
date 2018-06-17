using System;
using System.Drawing;
using System.Collections;
using System.ComponentModel;
using System.Windows.Forms;
using System.Data;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace TestXOR
{
	/// <summary>
	/// Form1 ��ժҪ˵����
	/// </summary>
	public class Form1 : System.Windows.Forms.Form
	{
        private System.Windows.Forms.Button btnOpen;
        private System.Windows.Forms.Button btnAnalyze;
        private System.Windows.Forms.Button btnReGen;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.NumericUpDown nuLength;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox txKey;
        private System.Windows.Forms.TextBox txContext;
        private System.Windows.Forms.TextBox txResult;
        private System.Windows.Forms.OpenFileDialog ofd;
        private System.Windows.Forms.TextBox txEncrypted;
		/// <summary>
		/// ����������������
		/// </summary>
		private System.ComponentModel.Container components = null;

		public Form1()
		{
			//
			// Windows ���������֧���������
			//
			InitializeComponent();

			//
			// TODO: �� InitializeComponent ���ú�����κι��캯������
			//
            RegenKey();
		}

		/// <summary>
		/// ������������ʹ�õ���Դ��
		/// </summary>
		protected override void Dispose( bool disposing )
		{
			if( disposing )
			{
				if (components != null) 
				{
					components.Dispose();
				}
			}
			base.Dispose( disposing );
		}

		#region Windows ������������ɵĴ���
		/// <summary>
		/// �����֧������ķ��� - ��Ҫʹ�ô���༭���޸�
		/// �˷��������ݡ�
		/// </summary>
		private void InitializeComponent()
		{
            this.btnOpen = new System.Windows.Forms.Button();
            this.btnAnalyze = new System.Windows.Forms.Button();
            this.btnReGen = new System.Windows.Forms.Button();
            this.label1 = new System.Windows.Forms.Label();
            this.nuLength = new System.Windows.Forms.NumericUpDown();
            this.label2 = new System.Windows.Forms.Label();
            this.txKey = new System.Windows.Forms.TextBox();
            this.txContext = new System.Windows.Forms.TextBox();
            this.txResult = new System.Windows.Forms.TextBox();
            this.ofd = new System.Windows.Forms.OpenFileDialog();
            this.txEncrypted = new System.Windows.Forms.TextBox();
            ((System.ComponentModel.ISupportInitialize)(this.nuLength)).BeginInit();
            this.SuspendLayout();
            // 
            // btnOpen
            // 
            this.btnOpen.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnOpen.Location = new System.Drawing.Point(512, 48);
            this.btnOpen.Name = "btnOpen";
            this.btnOpen.TabIndex = 0;
            this.btnOpen.Text = "Open File";
            this.btnOpen.Click += new System.EventHandler(this.btnOpen_Click);
            // 
            // btnAnalyze
            // 
            this.btnAnalyze.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnAnalyze.Location = new System.Drawing.Point(512, 80);
            this.btnAnalyze.Name = "btnAnalyze";
            this.btnAnalyze.Size = new System.Drawing.Size(75, 40);
            this.btnAnalyze.TabIndex = 1;
            this.btnAnalyze.Text = "Start Analyze";
            this.btnAnalyze.Click += new System.EventHandler(this.btnAnalyze_Click);
            // 
            // btnReGen
            // 
            this.btnReGen.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnReGen.Location = new System.Drawing.Point(512, 16);
            this.btnReGen.Name = "btnReGen";
            this.btnReGen.TabIndex = 2;
            this.btnReGen.Text = "ReGen Key";
            this.btnReGen.Click += new System.EventHandler(this.btnReGen_Click);
            // 
            // label1
            // 
            this.label1.Location = new System.Drawing.Point(8, 16);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(136, 23);
            this.label1.TabIndex = 4;
            this.label1.Text = "key length in Bytes";
            // 
            // nuLength
            // 
            this.nuLength.Location = new System.Drawing.Point(136, 16);
            this.nuLength.Maximum = new System.Decimal(new int[] {
                                                                     16,
                                                                     0,
                                                                     0,
                                                                     0});
            this.nuLength.Minimum = new System.Decimal(new int[] {
                                                                     1,
                                                                     0,
                                                                     0,
                                                                     0});
            this.nuLength.Name = "nuLength";
            this.nuLength.Size = new System.Drawing.Size(64, 21);
            this.nuLength.TabIndex = 5;
            this.nuLength.Value = new System.Decimal(new int[] {
                                                                   5,
                                                                   0,
                                                                   0,
                                                                   0});
            this.nuLength.ValueChanged += new System.EventHandler(this.nuLength_ValueChanged);
            // 
            // label2
            // 
            this.label2.Location = new System.Drawing.Point(208, 16);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(32, 23);
            this.label2.TabIndex = 6;
            this.label2.Text = "Key:";
            // 
            // txKey
            // 
            this.txKey.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
                | System.Windows.Forms.AnchorStyles.Right)));
            this.txKey.Location = new System.Drawing.Point(240, 16);
            this.txKey.Name = "txKey";
            this.txKey.ReadOnly = true;
            this.txKey.Size = new System.Drawing.Size(256, 21);
            this.txKey.TabIndex = 7;
            this.txKey.Text = "";
            // 
            // txContext
            // 
            this.txContext.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
                | System.Windows.Forms.AnchorStyles.Right)));
            this.txContext.Location = new System.Drawing.Point(8, 48);
            this.txContext.Multiline = true;
            this.txContext.Name = "txContext";
            this.txContext.ReadOnly = true;
            this.txContext.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.txContext.Size = new System.Drawing.Size(488, 152);
            this.txContext.TabIndex = 8;
            this.txContext.Text = "";
            // 
            // txResult
            // 
            this.txResult.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
                | System.Windows.Forms.AnchorStyles.Left) 
                | System.Windows.Forms.AnchorStyles.Right)));
            this.txResult.Location = new System.Drawing.Point(8, 368);
            this.txResult.Multiline = true;
            this.txResult.Name = "txResult";
            this.txResult.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.txResult.Size = new System.Drawing.Size(488, 56);
            this.txResult.TabIndex = 9;
            this.txResult.Text = "";
            // 
            // txEncrypted
            // 
            this.txEncrypted.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
                | System.Windows.Forms.AnchorStyles.Right)));
            this.txEncrypted.Location = new System.Drawing.Point(8, 208);
            this.txEncrypted.Multiline = true;
            this.txEncrypted.Name = "txEncrypted";
            this.txEncrypted.ReadOnly = true;
            this.txEncrypted.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.txEncrypted.Size = new System.Drawing.Size(488, 152);
            this.txEncrypted.TabIndex = 8;
            this.txEncrypted.Text = "";
            // 
            // Form1
            // 
            this.AutoScaleBaseSize = new System.Drawing.Size(6, 14);
            this.ClientSize = new System.Drawing.Size(600, 429);
            this.Controls.Add(this.txResult);
            this.Controls.Add(this.txContext);
            this.Controls.Add(this.txKey);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.nuLength);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.btnReGen);
            this.Controls.Add(this.btnAnalyze);
            this.Controls.Add(this.btnOpen);
            this.Controls.Add(this.txEncrypted);
            this.Name = "Form1";
            this.Text = "Form1";
            ((System.ComponentModel.ISupportInitialize)(this.nuLength)).EndInit();
            this.ResumeLayout(false);

        }
		#endregion

		/// <summary>
		/// Ӧ�ó��������ڵ㡣
		/// </summary>
		[STAThread]
		static void Main() 
		{
			Application.Run(new Form1());
		}

        private byte[]  key = new byte[0];
        private byte[]  encrypted = new byte[0];
        private int[]   blend = new int[256];
        private byte[]  blendOrder = new byte[256];
        private int[]   plain = new int[256];
        private int[]   plainOrdered = new int[256];
        private byte[]  plainOrder = new byte[256];
        private byte[]  blendBuff = new byte[0];
        private int    buffLen, guessLen;

        /// <summary>
        /// ��һ���ļ�����Ϊ����Ĵ��������ġ���ͬʱ��Ϊ��ĸƵ�ʣ���ϢƵ�ʣ�����������
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnOpen_Click(object sender, System.EventArgs e)
        {
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                StreamReader sr = new StreamReader(ofd.FileName, Encoding.Default);
                try
                {
                    txContext.Text = sr.ReadToEnd();
                }
                finally
                {
                    sr.Close();
                }
            }
        }

        /// <summary>
        /// ���������µ������Կ
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnReGen_Click(object sender, System.EventArgs e)
        {
            RegenKey();
        }

        /// <summary>
        /// ���������Կ�ĺ������ú�����ǿ��������з������õ��ģ�
        /// ����ͨ��Random�����ṩ����������Ӿ�����ѧ�����ϵ�����ԡ�
        /// </summary>
        private void RegenKey()
        {
            int i, len = (int) nuLength.Value;
            key = new byte[len];
            StringBuilder sb = new StringBuilder();
            RNGCryptoServiceProvider.Create().GetBytes(key);
            for (i = 0; i < len; i++)
            {
                sb.Append(key[i].ToString("X2") + " ");
            }
            sb.Remove(sb.Length - 1, 1);
            txKey.Text = sb.ToString();
        }

        /// <summary>
        /// ����Կ�������ñ��ı��ʱ�������µ���Կ��
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void nuLength_ValueChanged(object sender, System.EventArgs e)
        {
            RegenKey();
        }

        /// <summary>
        /// �û�����ˡ���������ť֮�󣬽������������
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnAnalyze_Click(object sender, System.EventArgs e)
        {
            if (txContext.Text.Length == 0) return;
            txResult.Text += "Start analyzing...\r\n";
            Encrypt();
            Analyze(1, 16);
            txResult.Text += "\r\n";
        }
        
        /// <summary>
        /// ���ܺ�����һ���ǳ����͵������ܷ�����
        /// </summary>
        private void Encrypt()
        {
            encrypted = Encoding.Default.GetBytes(txContext.Text);
            buffLen = encrypted.Length;
            int klen = key.Length;
            int i, len = encrypted.Length;
            byte curByte;
            if (klen == 0) return;

            txResult.Text += "\tEncrypting...\r\n";
            for (i = 0; i < len; i++)
            {
                curByte = encrypted[i];
                if (curByte != 0)
                    encrypted[i] = (byte) (curByte ^ key[i % klen]);
            }

            txEncrypted.Text = Encoding.Default.GetString(encrypted);
        }

        /// <summary>
        /// �²���Կ���ȵĺ������²���������guessLen���С�
        /// ͬʱ�����Դ˲²ⳤ�Ƚ�������λ�����������Կ�Ĺ��̡�
        /// ��������Կ֮�����Ϣ������blendBuff�����ڡ�
        /// ͬʱ����������е���Ϣ����ͳ�ƣ����ݳ��ֵĴ����Զ�����ֵ������Ӧ������
        /// �����Ľ��������blend���鵱�У�����ÿһ��Ԫ������Ӧ�Ķ�����ֵ�����blendOrder���С�
        /// </summary>
        /// <param name="From">�²ⳤ����Сֵ</param>
        /// <param name="To">�²ⳤ�����ֵ</param>
        private void GuessLength(int From, int To)
        {
            int [,] hack = new int[To - From + 1, 256];
            byte[] buff = encrypted;
            int i, j;

            txResult.Text += "\tFinding key length...\r\n\t\tXor with shifting...\r\n";
            Application.DoEvents();
            for (i = 0; i < buffLen; i++)
            {
                byte cur = buff[i];
                for (j = From; j <= To; j++)
                {
                    byte result = (byte) (cur ^ buff[(i + j) % buffLen]);
                    hack[j - From, result]++;
                }
            }
            txResult.Text += "\t\tAnalyzing xor results...\r\n\t\t";
            Application.DoEvents();

            double average, diff, tmp;
            double maxDiff;
            int     maxLen;
            StringBuilder sb = new StringBuilder();
            average = buffLen / 256;
            average *= average;
            maxDiff = 0; //double.MaxValue;
            maxLen = 0;
            for (i = 0; i < To - From + 1; i++)
            {
                diff = 0;
                for (j = 0; j < 256; j++)
                {
                    tmp = hack[i, j];
                    tmp *= tmp;
                    diff += tmp - average;
                }
                sb.AppendFormat("{0}:{1} ", i + From, diff);
                if (diff > maxDiff)
                {
                    maxDiff = diff;
                    maxLen = i + From;
                }
            }
            txResult.Text += sb.ToString();
            Application.DoEvents();
            sb.Length = 0;

            txResult.Text += "\r\nGuess Length = " + maxLen.ToString() + " (It might be the multiple of the real length) \r\n\t";
            Application.DoEvents();

            j = maxLen - From;
            for (i = 0; i < 256; i++)
            {
                blend[i] = hack[j, i];
            }
            guessLen = maxLen;

            for (i = 0; i < 256; i++)
            {
                blendOrder[i] = (byte) i;
                sb.AppendFormat("{0:00000} ", blend[i]);
                if ((i % 16) == 15)
                {
                    sb.Append("\r\n\t");
                }
            }
            Array.Sort(blend, blendOrder);
            txResult.Text += sb.ToString();
            Application.DoEvents();
            sb.Length = 0;
            for (i = 255; i >=0 ; i--)
            {
                sb.AppendFormat("{0:0000}({1:000}), ", blend[i], blendOrder[i]);
                if ((i % 8) == 0)
                {
                    sb.Append("\r\n\t");
                }
            }
            Array.Reverse(blend);
            Array.Reverse(blendOrder);
            sb.Remove(sb.Length - 1, 1);
            txResult.Text += sb.ToString();
            Application.DoEvents();
            sb.Length = 0;

            blendBuff = new byte[buffLen];
            for (i = 0; i < buffLen; i++)
            {
                blendBuff[i] = (byte) (encrypted[i] ^ encrypted[(i + maxLen) % buffLen]);
            }
        }

        /// <summary>
        /// �������������з����ĺ�����
        /// �ú���Ŀǰ�����Ա����ܵ����Ľ���ͳ�ƣ�ʵ����ֻ��Ҫ�뱻�����������Ƶ��ı����ɡ�
        /// ����������Ǳ��������ı������൱�ڽ���ѡ�����Ĺ�����
        /// ������������뱻�����������Ƶ��ı������൱������������֪���Ĺ�����
        /// �ú����ķ������������plain���鵱�У���ÿһ����ĸ���ֵĴ�����
        /// ������Ľ��������plainOrdered���飬���Ӧ�Ķ�����ֵ������plainOrder�����С�
        /// </summary>
        private void CountingPlainText()
        {
            byte[] textBuff = Encoding.Unicode.GetBytes(txContext.Text);
            int i;
            StringBuilder sb = new StringBuilder();

            txResult.Text += "Counting source text...\r\n\t";
            plain.Initialize();
            for (i = 0; i < buffLen; i++)
            {
                plain[textBuff[i]]++;
            }
            for (i = 0; i < 256; i++)
            {
                plainOrder[i] = (byte) i;
                sb.AppendFormat("{0:00000} ", plain[i]);

                if ((i % 16) ==15)
                {
                    sb.Append("\r\n\t");
                }
            }
            txResult.Text += sb.ToString();
            Application.DoEvents();
            sb.Length = 0;

            txResult.Text += "Ordered:\r\n\t";
            Array.Copy(plain, 0, plainOrdered,0, 256);
            Array.Sort(plainOrdered, plainOrder);
            for (i = 255; i >= 0; i--)
            {
                sb.AppendFormat("{0:0000}({1:000}), ", plainOrdered[i], plainOrder[i]);
                if ((i % 8) == 0)
                {
                    sb.Append("\r\n\t");
                }
            }
            Array.Reverse(plainOrdered);
            Array.Reverse(plainOrder);
            sb.Remove(sb.Length - 1, 1);
            txResult.Text += sb.ToString();
            Application.DoEvents();
            sb.Length = 0;
        }

        /// <summary>
        /// �²�һ������϶ԡ���
        /// ��ν�Ļ�϶�ʵ���Ͼ�������������Ϣ֮���������������ҳ�֮ΪBlend��
        /// ����������Ϣһ��ΪAlpha������һ��ΪBeta��
        /// �ú�����Ҫ�ҳ������ض�Blendֵ����Ϊ���ܵ�Alphaֵ��Betaֵ��
        /// �õ�Alphaֵ��Betaֵ��Ҫ����Ϊ�˽��к������Կ�²⣬
        /// ��Ϊһ��֪������ܵ�Alphaֵ��Betaֵ��������Ƶ�������ܵ���ԿֵK��
        /// �㷨�Ľ�����μ��ڲ�ע�͡�
        /// </summary>
        /// <param name="Index">Blend��������ֵԽС����ʾ��Blendֵ���ֵ�Խ�ࡣҲ��Խ���ܱ��ɹ���������Ӧ����Կֵ</param>
        /// <returns>����һ������Blend��Alpha��Beta�Ķ������е�Alpha��Beta������ܳ��ֵġ�</returns>
        private BlendToken GuessBlendGene(int Index)
        {
            int count = 0;
            int i, j;
            int blendx;
            long val;
            long maxValue = 0;
            BlendToken result = null;

            txResult.Text += "Guessing one blend token...\r\n\t"; 

            // ����Index��Ҫ���ҳ����ִ�����Index���Blendֵ��
            for (i = 0; i < 256; i++)
            {
                // ������Ҫ����BlendֵΪ0�Ĳ��֣���Ϊ���ռ����㷨��
                // ���ǿ��Կ���������ֵΪ��������ǲ������Կ���ģ�
                // ��blend=0�ܿ���������alpha = 0, beta = 0��ɵģ�
                // ��Щblendֵ�����Ͳ�������Կ��Ϣ����˶������������û�а�����
                // �������к��ģ����ܻ����������Ľ������Ҫ������
                if (blendOrder[i] == 0)
                {
                    continue;
                }
                if (count == Index)
                {
                    break;
                }
                count++;
            }
            if (count >= 256) return null;

            blendx = blendOrder[i];
            // �������ѭ�������ҵ�����ܵ�alpha/beta�ԡ����е�i/j���൱��alpha��beta��
            // ���alpha����betaΪ�㣬������Ĳ������Կ����������Ӧ���ų����⡣
            // ����²���Կ��ʱ�����Ϊ����Կ������򣬵õ�һ����ʵ�ʲ����ϵĽ������ɲ²����
            // ���i��������0����1��ʼ�������j = 0Ҳ��Ҫ����������
            for (i = 1; i < 256; i++)
            {
                // ��Ϊ alpha xor beta == blend�����beta = blend xor alpha��
                j = blendx ^ i;
                if (j == 0) continue;
                // ����alpha���ֵĸ���Ϊalpha'����alpha' = plain[alpha]������beta��ͬ��
                val = plain[i];
                // ���������ȣ���ô����ֵĸ��ʵ���alpha' * (alpha' - 1) / 2��
                // ������ָ���Ӧ�õ��� alpha' * beta'
                // val�������൱��alpha'
                // ��������֮���val���ڳ��ָ��ʡ�
                if (i == j)
                {
                    val *= val - 1;
                    val >>= 1;
                }
                else
                {
                    val *= plain[j];
                }
                // ���������ʱ�������ͳ�Ƹ�����������alpha/beta�Ը��п��ܳ��֡�
                if (val > maxValue)
                {
                    maxValue = val;
                    result = new BlendToken((byte) i, (byte) j);
                }
            }
            // ��ʾ��alpha/beta�Ե����������blendֵ����Ϣ��
            txResult.Text += string.Format("Blend = {0:000}, Alpha = {1:000}({2:0000}), Beta = {3:000}({4:0000})\r\n\t", blendx, result.Alpha, plain[result.Alpha], result.Beta, plain[result.Beta]);
            Application.DoEvents();
            return result;
        }

        /// <summary>
        /// ����һ��BlendToken�²���ܵ���Կ�����
        /// �ú��������л�����μ��ڲ�˵����
        /// </summary>
        /// <param name="token">����Blend��Alpha��Betaֵ��һ������</param>
        /// <returns>����һ�Կ��ܵ���Կ����塣���������μ��ڲ�ע�͡�</returns>
        private int[,] GuessKeyInternal(BlendToken token)
        {
            int[,] resultKey = new int[2, guessLen];
            int[,] guessBox = new int[guessLen, 256];
            int i, blendx, encryptx, keyIndex;

            // ��������blend������з�����
            for (i = 0; i < buffLen; i++)
            {
                // ��ǰ��blendֵΪblendx
                blendx = blendBuff[i];
                // �����BlendToken������ָ����blendֵ������з���
                if (blendx == token.Blend)
                {
                    // ����� i % guessLen λ�õ���ԿΪ k
                    // ��λ�÷ֱ�Ϊ i �Լ� i+guessLen �����ķֱ��alpha��beta�������
                    // ����ܵõ� k ���� k xor alpha xor beta
                    // �������£�
                    // ���� a, b �ֱ����Կ k ������򣬷ֱ�õ����� c, d
                    // ���ڲ������жϳ�alpha��a����b������п��ܲ����������ֽ����
                    // 1��a xor k = c
                    //    b xor k = d
                    //    c xor alpha = c xor a = a xor k xor a = k
                    //    d xor beta = d xor b = b xor k xor b = k
                    // 2��a xor k = c
                    //    b xor k = d
                    //    c xor alpha = c xor b = a xor k xor b = k xor alpha xor beta
                    //    d xor beta = d xor a = b xor k xor a = k xor alpha xor beta
                    // ��������һ�����������ֵ����Ȼ��ȡ��������ֱ����alpha��beta֮�󣬷���ֵ��ȣ�
                    // ����ܲ²���ȷ���ϸ�˵Ӧ����alpha��beta���ܲ²���ȷ��Ҳ�����������Ŀ��ܱ��²������
                    // ����˳��ȴ���ܹ�ȷ������
                    encryptx = encrypted[i];
                    if ((encryptx ^ token.Alpha) == (encrypted[(i + guessLen) % buffLen] ^ token.Beta))
                    {
                        keyIndex = i % guessLen;
                        // ��ʱ�Ը�λ�õĿ�����Կ���м�������һ��
                        // encryptx xor alpha �� encryptx xor beta �ֱ�õ� k �� k xor alpha xor beta��
                        // �����޷�ȷ����һ���� k����һ���� k xor alpha xor beta��
                        guessBox[keyIndex, encryptx ^ token.Alpha]++;
                        guessBox[keyIndex, encryptx ^ token.Beta]++;
                    }
                }
            }

            int  j;
            int  count, maxCount, maxValue;

            // ȫ�ķ������֮�����Ƕ�ÿһ��λ�õ���Կ����������з�����
            // �����ԣ�k �Լ� k xor alpha xor beta���������Ŀ���������ߵģ�
            // �����ļ�ʹ��Ҳֻ��������ֵ�����
            // i ѭ������ÿһλ����Կ��j ѭ������һ����ֵ����������Կ
            for (i = 0; i < guessLen; i++)
            {
                maxCount = 0;
                maxValue = -1;
                for (j = 0; j < 256; j++)
                {
                    count = guessBox[i,j];
                    if (count == 0) continue;
                    // ������ִ�����ԭ�����������ԿֵҪ�࣬��ô�����Կ����������������Կ
                    if (count > maxCount)
                    {
                        maxCount = count;
                        maxValue = j;
                    }
                }
                if (maxCount > 0)
                {
                    // ����ҵ��ˣ������ֵ�� g��
                    // �����޷��ж���� g ������ k ���� k xor alpha xor beta
                    // �������ֻ�ܹ����� g �� g xor alpha xor beta ���ǿ��ܵ���Կֵ
                    // ��������¼��������Կ��
                    resultKey[0, i] = maxValue;
                    resultKey[1, i] = (byte) (maxValue ^ token.Alpha ^ token.Beta);
                }
                else
                {
                    // ����Ҳ���������һ����־
                    resultKey[0, i] = -1;
                    resultKey[1, i] = -1;
                }
            }

            // ���緵�ص��� [a b c] [d e f] ���������飬��
            // a b c
            // d e f
            // a e c
            // �ȵȶ��ǿ��ܵ���Կֵ�����Ǵ�ʱ����Կ�������Ѿ����ֳ����ˣ�ʣ�µĲ²�ͺܼ��ˡ�
            return resultKey;
        }

        /// <summary>
        /// ��ʼ�������������
        /// </summary>
        /// <param name="From">�²���Կ���ȵ���Сֵ</param>
        /// <param name="To">�²���Կ���ȵ����ֵ</param>
        private void Analyze(int From, int To)
        {
            BlendToken token;
            CountingPlainText();
            GuessLength(From, To);

            // ��������ֻ������ܵ�һ��BlendToken����һ�β²⡣ʵ���Ͽ������ø����ӡ�

            token = GuessBlendGene(0);
            if (token == null)
            {
                MessageBox.Show("Failed finding blend gene!");
                return;
            }

            int[,] key;
            key = GuessKeyInternal(token);
            txResult.Text += "Possible key groups:\r\n\t";
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < guessLen; j++)
                {
                    txResult.Text += key[i,j].ToString("X2") + " ";
                }
                txResult.Text += "\r\n\t";
            }
        }
	}
}
