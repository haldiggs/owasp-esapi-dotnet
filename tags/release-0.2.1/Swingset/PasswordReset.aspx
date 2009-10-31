<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="PasswordReset.aspx.cs" Inherits="Owasp.Esapi.Swingset.PasswordReset" MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="PasswordResetContent" ContentPlaceHolderID="SwingsetContentPlaceHolder" runat="server">
    Please answer the secret question and create a new password.
    Secret Question
    <div>
        <asp:Label ID="lblSecretQuestion" runat="server"></asp:Label>
    </div>
    Secret Answer
    <div>
        
        <asp:TextBox ID="txtSecretAnswer" runat="server"></asp:TextBox>
    </div>
    New Password
    <div>
        <asp:RegularExpressionValidator ID="rgxvNewPassword" runat="server" 
            ErrorMessage="The password must be greater than eight characters and include one upper-case letter, one lower-case letter, one number, and one special character."
            ValidationExpression="^(?=.{8,})(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*\W).*$"
            ControlToValidate="txtNewPassword" />
        <asp:TextBox ID="txtNewPassword" runat="server" TextMode="Password"></asp:TextBox>
    </div>
    New Password Confirmation
    <div>
        <asp:CompareValidator ID="cmpvConfirmNewPassword" runat="server" 
            ErrorMessage="Password and password confirmation must match."
            ControlToValidate="txtConfirmNewPassword" ControlToCompare="txtNewPassword">
        </asp:CompareValidator>
        <asp:TextBox ID="txtConfirmNewPassword" runat="server" TextMode="Password"></asp:TextBox>
    </div>
    <div>
        <asp:Button ID="btnSubmit" runat="server" Text="Submit" 
            onclick="btnSubmit_Click" />
    </div>
    <asp:Label ID="lblError" runat="server"></asp:Label>
</asp:Content>