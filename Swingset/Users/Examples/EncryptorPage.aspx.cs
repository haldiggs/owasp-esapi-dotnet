using System;
using Owasp.Esapi.Errors;

namespace Owasp.Esapi.Swingset.Users.Examples
{
    public partial class EncryptorPage : SwingsetPage
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            lblErrorMessage.Text = "";
        }

        protected void btnCompute_Click(object sender, EventArgs e)
        {
            try
            {
                txtCiphertext.Text = Esapi.Encryptor.Encrypt(txtPlaintext.Text);
                txtHash.Text = Esapi.Encryptor.Hash(txtPlaintext.Text, ""); // You could use a salt here
                txtSignature.Text = Esapi.Encryptor.Sign(txtPlaintext.Text);
                txtSeal.Text = Esapi.Encryptor.Seal(txtPlaintext.Text, Esapi.Encryptor.TimeStamp + 10 * 1000 * 10000); // You can set an arbitrary amount of time, this will stay valid for 10 seconds
            }
            catch (EnterpriseSecurityException ese)
            {
                lblErrorMessage.Text = ese.Message;
            }
        }

        protected void btnDecrypt_Click(object sender, EventArgs e)
        {
            try
            {
                txtPlaintext.Text = Esapi.Encryptor.Decrypt(txtCiphertext.Text);
            }
            catch (EnterpriseSecurityException ese)
            {
                lblErrorMessage.Text = ese.Message;
            }
        }

        protected void btnVerifySignature_Click(object sender, EventArgs e)
        {
            try
            {
                if (Esapi.Encryptor.VerifySignature(txtSignature.Text, txtPlaintext.Text))
                {
                    lblErrorMessage.Text = "Signature is valid.";
                }
                else
                {
                    lblErrorMessage.Text = "Signature is not valid.";
                }

            }
            catch (EnterpriseSecurityException ese)
            {
                lblErrorMessage.Text = ese.Message;
            }
        }


        protected void btnVerifySeal_Click(object sender, EventArgs e)
        {
            try
            {
                if (Esapi.Encryptor.VerifySeal(txtSeal.Text))
                {
                    lblErrorMessage.Text = "Seal verified.";
                }
                else
                {
                    lblErrorMessage.Text = "Seal is not valid.";
                }

            }
            catch (EnterpriseSecurityException ese)
            {
                lblErrorMessage.Text = ese.Message;
            }
        }

    }
}
