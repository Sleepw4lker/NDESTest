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
using CERTCLILib;
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
            const int CR_IN_BASE64HEADER = 0;
            const int CR_IN_BASE64 = 1;
            const int CR_IN_PKCS7 = 0x300;
            const int CR_IN_SCEP = 0x00010000;
            const int CR_IN_SCEPPOST = 0x02000000; // Pass CR_IN_SCEP for the first argument, and optionally bit-wise OR in CR_IN_SCEPPOST if your server supports POST

            //const int CR_DISP_INCOMPLETE = 0; // Request did not complete
            //const int CR_DISP_ERROR = 1; // Request failed
            const int CR_DISP_DENIED = 2; // Request denied
            const int CR_DISP_ISSUED = 3; // Certificate issued
            //const int CR_DISP_ISSUED_OUT_OF_BAND = 4; // Certificate issued separately
            //const int CR_DISP_UNDER_SUBMISSION = 5; // Request taken under submission

            const int SCEPProcessDefault = 0x0;
            const int SCEPProcessSkipCertInstall = 0x1;

            string protocol;

            if (checkBox1.Checked)
                protocol = "https";
            else
                protocol = "http";

            var sConfigString = protocol + "://" + textBox1.Text + "/certsrv/mscep/mscep.dll/pkiclient.exe";

            var oCertRequestPkcs10 = new CX509CertificateRequestPkcs10();

            oCertRequestPkcs10.Initialize(CERTENROLLLib.X509CertificateEnrollmentContext.ContextUser);

            var oSubjectDN = new CX500DistinguishedName();
            oSubjectDN.Encode("CN=TestNDESCert");

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
                    MessageBox.Show("Issued");
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
