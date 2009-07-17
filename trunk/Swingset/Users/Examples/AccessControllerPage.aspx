<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="AccessControllerPage.aspx.cs" Inherits="Owasp.Esapi.Swingset.Users.Examples.AccessControllerPage" MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="AccessControllerContent" ContentPlaceHolderID="SwingsetContentPlaceHolder" runat="server">    
    <fieldset>
    Resources:
    <div>
    <asp:ListBox ID="lbResources" runat="server"></asp:ListBox>
    </div>
    Actions:
    <div>
    <asp:ListBox ID="lbActions" runat="server"></asp:ListBox>
    </div>
    <asp:Button ID="btnAdd" runat="server" Text="Add Permission" 
        onclick="btnAdd_Click"></asp:Button>
    <asp:Button ID="btnCheck" runat="server" Text="Check Permission" 
        onclick="btnCheck_Click"></asp:Button>
        <p><asp:Label ID="lblResult" runat="server" Text=""></asp:Label></p>
    </fieldset>
    <fieldset>
    Permissions:
    <div><asp:ListBox ID="lbPermissions" runat="server"></asp:ListBox></div>
    <asp:Button ID="btnRemove" runat="server" Text="Remove Permission" 
        onclick="btnRemove_Click"></asp:Button>
    </fieldset>
</asp:Content>