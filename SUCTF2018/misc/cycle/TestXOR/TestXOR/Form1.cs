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
	/// Form1 的摘要说明。
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
		/// 必需的设计器变量。
		/// </summary>
		private System.ComponentModel.Container components = null;

		public Form1()
		{
			//
			// Windows 窗体设计器支持所必需的
			//
			InitializeComponent();

			//
			// TODO: 在 InitializeComponent 调用后添加任何构造函数代码
			//
            RegenKey();
		}

		/// <summary>
		/// 清理所有正在使用的资源。
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

		#region Windows 窗体设计器生成的代码
		/// <summary>
		/// 设计器支持所需的方法 - 不要使用代码编辑器修改
		/// 此方法的内容。
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
		/// 应用程序的主入口点。
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
        /// 打开一个文件，做为假设的待加密明文。（同时作为字母频率（信息频率）检验样本）
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
        /// 重新生成新的随机密钥
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnReGen_Click(object sender, System.EventArgs e)
        {
            RegenKey();
        }

        /// <summary>
        /// 生成随机密钥的函数，该函数用强随机数序列发生器得到的，
        /// 比普通的Random类所提供的随机数更加具有数学意义上的随机性。
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
        /// 当密钥长度设置被改变的时候，生成新的密钥。
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void nuLength_ValueChanged(object sender, System.EventArgs e)
        {
            RegenKey();
        }

        /// <summary>
        /// 用户点击了“分析”按钮之后，进行密码分析。
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
        /// 加密函数，一个非常典型的异或加密方法。
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
        /// 猜测密钥长度的函数。猜测结果保存在guessLen当中。
        /// 同时还有以此猜测长度进行密文位移异或，消除密钥的过程。
        /// 消除了密钥之后的信息保存在blendBuff数组内。
        /// 同时对这个数组中的信息进行统计，根据出现的次数对二进制值进行相应的排序。
        /// 排序后的结果保存在blend数组当中，其中每一个元素所对应的二进制值存放在blendOrder当中。
        /// </summary>
        /// <param name="From">猜测长度最小值</param>
        /// <param name="To">猜测长度最大值</param>
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
        /// 对明文样本进行分析的函数。
        /// 该函数目前仅仅对被加密的明文进行统计，实际上只需要与被加密明文相似的文本即可。
        /// 如果分析的是被加密明文本身，就相当于进行选择明文攻击。
        /// 如果分析的是与被加密明文类似的文本，就相当于有条件的已知密文攻击。
        /// 该函数的分析结果保存在plain数组当中，即每一个字母出现的次数。
        /// 排序过的结果保存在plainOrdered数组，其对应的二进制值保存在plainOrder数组中。
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
        /// 猜测一个“混合对”。
        /// 所谓的混合对实际上就是两个明文信息之间的异或，在这里面我称之为Blend，
        /// 两个明文信息一个为Alpha，另外一个为Beta。
        /// 该函数主要找出对于特定Blend值，最为可能的Alpha值和Beta值。
        /// 得到Alpha值和Beta值主要就是为了进行后面的密钥猜测，
        /// 因为一旦知道最可能的Alpha值和Beta值，则可以推导出最可能的密钥值K。
        /// 算法的解释请参见内部注释。
        /// </summary>
        /// <param name="Index">Blend索引，数值越小，表示该Blend值出现的越多。也就越可能被成功分析出相应的密钥值</param>
        /// <returns>返回一个包含Blend、Alpha、Beta的对象，其中的Alpha和Beta是最可能出现的。</returns>
        private BlendToken GuessBlendGene(int Index)
        {
            int count = 0;
            int i, j;
            int blendx;
            long val;
            long maxValue = 0;
            BlendToken result = null;

            txResult.Text += "Guessing one blend token...\r\n\t"; 

            // 按照Index的要求，找出出现次数第Index多的Blend值。
            for (i = 0; i < 256; i++)
            {
                // 我们需要忽略Blend值为0的部分，因为按照加密算法，
                // 我们可以看到对于数值为零的明文是不会跟密钥异或的，
                // 而blend=0很可能是由于alpha = 0, beta = 0造成的，
                // 这些blend值根本就不包含密钥信息，因此对密码分析根本没有帮助，
                // 甚至是有害的，可能会分析出错误的结果。需要跳过。
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
            // 下面这个循环用于找到最可能的alpha/beta对。其中的i/j就相当于alpha和beta。
            // 如果alpha或者beta为零，则该明文不会和密钥进行异或，因此应该排除在外。
            // 否则猜测密钥的时候会因为跟密钥进行异或，得到一个和实际不符合的结果，造成猜测错误。
            // 因此i必须跳过0，从1开始，而如果j = 0也需要跳过分析。
            for (i = 1; i < 256; i++)
            {
                // 因为 alpha xor beta == blend，因此beta = blend xor alpha。
                j = blendx ^ i;
                if (j == 0) continue;
                // 假设alpha出现的概率为alpha'，则alpha' = plain[alpha]。对于beta有同理。
                val = plain[i];
                // 如果两者相等，那么其出现的概率等于alpha' * (alpha' - 1) / 2，
                // 否则出现概率应该等于 alpha' * beta'
                // val在上面相当于alpha'
                // 经过计算之后的val等于出现概率。
                if (i == j)
                {
                    val *= val - 1;
                    val >>= 1;
                }
                else
                {
                    val *= plain[j];
                }
                // 如果这个概率比以往的统计更大，则表明这个alpha/beta对更有可能出现。
                if (val > maxValue)
                {
                    maxValue = val;
                    result = new BlendToken((byte) i, (byte) j);
                }
            }
            // 显示该alpha/beta对的情况（包括blend值的信息）
            txResult.Text += string.Format("Blend = {0:000}, Alpha = {1:000}({2:0000}), Beta = {3:000}({4:0000})\r\n\t", blendx, result.Alpha, plain[result.Alpha], result.Beta, plain[result.Beta]);
            Application.DoEvents();
            return result;
        }

        /// <summary>
        /// 根据一个BlendToken猜测可能的密钥情况。
        /// 该函数的运行机制请参见内部说明。
        /// </summary>
        /// <param name="token">包含Blend、Alpha、Beta值的一个对象</param>
        /// <returns>返回一对可能的密钥混合体。具体解释请参见内部注释。</returns>
        private int[,] GuessKeyInternal(BlendToken token)
        {
            int[,] resultKey = new int[2, guessLen];
            int[,] guessBox = new int[guessLen, 256];
            int i, blendx, encryptx, keyIndex;

            // 对整个的blend数组进行分析。
            for (i = 0; i < buffLen; i++)
            {
                // 当前的blend值为blendx
                blendx = blendBuff[i];
                // 如果是BlendToken里面所指定的blend值，则进行分析
                if (blendx == token.Blend)
                {
                    // 假设第 i % guessLen 位置的密钥为 k
                    // 对位置分别为 i 以及 i+guessLen 的密文分别和alpha与beta进行异或，
                    // 则可能得到 k 或者 k xor alpha xor beta
                    // 依据如下：
                    // 明文 a, b 分别和密钥 k 进行异或，分别得到密文 c, d
                    // 由于不可能判断出alpha是a还是b，因此有可能产生下面两种结果：
                    // 1、a xor k = c
                    //    b xor k = d
                    //    c xor alpha = c xor a = a xor k xor a = k
                    //    d xor beta = d xor b = b xor k xor b = k
                    // 2、a xor k = c
                    //    b xor k = d
                    //    c xor alpha = c xor b = a xor k xor b = k xor alpha xor beta
                    //    d xor beta = d xor a = b xor k xor a = k xor alpha xor beta
                    // 无论是哪一种情况，两个值都必然相等。因此如果分别异或alpha和beta之后，发现值相等，
                    // 则可能猜测正确（严格说应该是alpha和beta可能猜测正确，也就是两个明文可能被猜测出来，
                    // 但是顺序却不能够确定！）
                    encryptx = encrypted[i];
                    if ((encryptx ^ token.Alpha) == (encrypted[(i + guessLen) % buffLen] ^ token.Beta))
                    {
                        keyIndex = i % guessLen;
                        // 此时对该位置的可能密钥进行计数（加一）
                        // encryptx xor alpha 和 encryptx xor beta 分别得到 k 和 k xor alpha xor beta，
                        // 但是无法确定哪一个是 k，哪一个是 k xor alpha xor beta。
                        guessBox[keyIndex, encryptx ^ token.Alpha]++;
                        guessBox[keyIndex, encryptx ^ token.Beta]++;
                    }
                }
            }

            int  j;
            int  count, maxCount, maxValue;

            // 全文分析完毕之后，我们对每一个位置的密钥可能情况进行分析。
            // 很明显，k 以及 k xor alpha xor beta被分析到的可能性是最高的，
            // 其他的即使有也只是随机出现的噪声
            // i 循环分析每一位的密钥，j 循环看哪一个数值更可能是密钥
            for (i = 0; i < guessLen; i++)
            {
                maxCount = 0;
                maxValue = -1;
                for (j = 0; j < 256; j++)
                {
                    count = guessBox[i,j];
                    if (count == 0) continue;
                    // 如果出现次数比原来假设可能密钥值要多，那么这个密钥更可能是真正的密钥
                    if (count > maxCount)
                    {
                        maxCount = count;
                        maxValue = j;
                    }
                }
                if (maxCount > 0)
                {
                    // 如果找到了，假设该值是 g，
                    // 由于无法判断这个 g 到底是 k 还是 k xor alpha xor beta
                    // 因此我们只能够假设 g 和 g xor alpha xor beta 都是可能的密钥值
                    // 因此这里记录了两个密钥组
                    resultKey[0, i] = maxValue;
                    resultKey[1, i] = (byte) (maxValue ^ token.Alpha ^ token.Beta);
                }
                else
                {
                    // 如果找不到，设置一个标志
                    resultKey[0, i] = -1;
                    resultKey[1, i] = -1;
                }
            }

            // 假如返回的是 [a b c] [d e f] 这两个数组，则：
            // a b c
            // d e f
            // a e c
            // 等等都是可能的密钥值。但是此时的密钥基本上已经浮现出来了，剩下的猜测就很简单了。
            return resultKey;
        }

        /// <summary>
        /// 开始进行密码分析。
        /// </summary>
        /// <param name="From">猜测密钥长度的最小值</param>
        /// <param name="To">猜测密钥长度的最大值</param>
        private void Analyze(int From, int To)
        {
            BlendToken token;
            CountingPlainText();
            GuessLength(From, To);

            // 这里我们只对最可能的一个BlendToken进行一次猜测。实际上可以做得更复杂。

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
