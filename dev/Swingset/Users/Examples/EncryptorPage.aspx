<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="EncryptorPage.aspx.cs" Inherits="Owasp.Esapi.Swingset.Users.Examples.EncryptorPage" MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="EncryptorContent" ContentPlaceHolderID="SwingsetContentPlaceHolder" runat="server">
    
    Plaintext:
    <div><asp:TextBox ID="txtPlaintext" runat="server"></asp:TextBox>   
    <asp:Button ID="btnCompute" runat="server" Text="Compute" 
            onclick="btnCompute_Click" /></div>
    
    Ciphertext:
    <div><asp:TextBox ID="txtCiphertext" runat="server"></asp:TextBox>
    <asp:Button ID="btnDecrypt" runat="server" Text="Decrypt" 
            onclick="btnDecrypt_Click" /></div>
    
    Hash:
    <div><asp:TextBox ID="txtHash" runat="server"></asp:TextBox></div>    
    Signature:
    <div><asp:TextBox ID="txtSignature" runat="server"></asp:TextBox>
    <asp:Button ID="btnVerifySignature" runat="server" Text="Verify" 
            onclick="btnVerifySignature_Click" /></div>

    Seal:
    <div><asp:TextBox ID="txtSeal" runat="server"></asp:TextBox>
    <asp:Button ID="btnVerifySeal" runat="server" Text="Verify" 
            onclick="btnVerifySeal_Click" /></div>

                
    <div><asp:Label ID="lblErrorMessage" runat="server" Text=""></asp:Label></div>
    
    
    
</asp:Content>