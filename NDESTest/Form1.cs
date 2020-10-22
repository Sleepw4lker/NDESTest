using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using CERTENROLLLib;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace NDESTest
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            const int SCEPProcessDefault = 0x0;
            //const int SCEPProcessSkipCertInstall = 0x1;

            string protocol;

            if (checkBox1.Checked)
                protocol = "https";
            else
                protocol = "http";

            var sConfigString = protocol + "://" + textBox1.Text + "/certsrv/mscep/mscep.dll/pkiclient.exe";

            var oCertRequestPkcs10 = new CX509CertificateRequestPkcs10();

            oCertRequestPkcs10.Initialize(CERTENROLLLib.X509CertificateEnrollmentContext.ContextUser);

            var oSubjectDN = new CX500DistinguishedName();
            oSubjectDN.Encode(textBox3.Text);

            oCertRequestPkcs10.Subject = oSubjectDN;
            oCertRequestPkcs10.PrivateKey.Length = 2048;
            oCertRequestPkcs10.PrivateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE;
            oCertRequestPkcs10.PrivateKey.KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_SIGNING_FLAG;

            oCertRequestPkcs10.KeyContainerNamePrefix = "NDESTest";
            
            if (checkBox2.Checked)
                oCertRequestPkcs10.ChallengePassword = textBox2.Text;

            var oEnrollmentHelper = new CX509SCEPEnrollmentHelper();

            try
            {
                oEnrollmentHelper.Initialize(
                    sConfigString,
                    "",
                    oCertRequestPkcs10,
                    ""
                    );
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                return;
            }

            var iDisposition = oEnrollmentHelper.Enroll(SCEPProcessDefault);


            switch (iDisposition)
            {
                case CERTENROLLLib.X509SCEPDisposition.SCEPDispositionFailure:
                    MessageBox.Show(oEnrollmentHelper.ResultMessageText.ToString());
                    break;

                case CERTENROLLLib.X509SCEPDisposition.SCEPDispositionSuccess:
                    
                    string base64 = oEnrollmentHelper.X509SCEPEnrollment.Certificate[EncodingType.XCN_CRYPT_STRING_BASE64];
                    X509Certificate2 cert = new X509Certificate2();
                    cert.Import(Convert.FromBase64String(base64));
                    X509Certificate2UI.DisplayCertificate(cert);
                    
                    break;
                default:
                    MessageBox.Show("Unknown");
                    break;
            }
        }

        private void checkBox2_CheckedChanged(object sender, EventArgs e)
        {
            textBox2.Enabled = checkBox2.Checked;
        }
    }
}
