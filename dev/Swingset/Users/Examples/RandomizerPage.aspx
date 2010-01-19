<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="RandomizerPage.aspx.cs" Inherits="Owasp.Esapi.Swingset.Users.Examples.RandomizerPage" MasterPageFile="~/Esapi.Master"%>
<asp:Content ID="RandomizerContent" ContentPlaceHolderID="SwingsetContentPlaceHolder" runat="server">
    <div><asp:Button ID="btnGenerate" runat="server" Text="Generate" 
            onclick="btnGenerate_Click" /></div>    
    bool:
    <div><asp:TextBox ID="txtbool" runat="server"></asp:TextBox></div>    
    
    Guid:
    <div><asp:TextBox ID="txtGuid" runat="server"></asp:TextBox></div>
    
    String:
    <div><asp:TextBox ID="txtString" runat="server"></asp:TextBox></div>    
    
    Integer:
    <div><asp:TextBox ID="txtInteger" runat="server"></asp:TextBox></div>

    Double:
    <div><asp:TextBox ID="txtDouble" runat="server"></asp:TextBox></div>

    Filename:
    <div><asp:TextBox ID="txtFilename" runat="server"></asp:TextBox></div>
                
    <div><asp:Label ID="lblErrorMessage" runat="server" Text=""></asp:Label></div>
</asp:Content>