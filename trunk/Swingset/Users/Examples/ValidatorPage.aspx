<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="ValidatorPage.aspx.cs" Inherits="Owasp.Esapi.Swingset.Users.Examples.ValidatorPage" MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="ValidatorContent" ContentPlaceHolderID="SwingsetContentPlaceHolder" runat="server">
    <fieldset>
    Credit Card:
    <div>
        <asp:TextBox ID="txtCreditCard" runat="server"></asp:TextBox>    
        <asp:CustomValidator ID="vldCreditCard" runat="server" ErrorMessage="Invalid credit card number." 
            ControlToValidate="txtCreditCard" OnServerValidate="vldCreditCard_ServerValidate" 
            ValidationGroup="creditCard" Display="Dynamic">
        </asp:CustomValidator>
        <asp:Label ID="lblCreditCardSuccess" runat="server" Text="Valid credit card number." Visible="false" CssClass="validation_success"></asp:Label>
    </div>
    <asp:Button ID="btnCreditCard" runat="server" Text="Validate" ValidationGroup="creditCard"/>
    </fieldset>
        
    <fieldset>
    Date:
    <div>
        <asp:TextBox ID="txtDate" runat="server"></asp:TextBox>    
        <asp:CustomValidator ID="vldDate" runat="server" ErrorMessage="Invalid date." 
            ControlToValidate="txtDate" OnServerValidate="vldDate_ServerValidate" 
            ValidationGroup="date" Display="Dynamic">
        </asp:CustomValidator>
        <asp:Label ID="lblDateSuccess" runat="server" Text="Valid date." Visible="false" CssClass="validation_success"></asp:Label>
        </div>
    <asp:Button ID="btnDate" runat="server" Text="Validate" ValidationGroup="date"/>
    </fieldset>
    
    <fieldset>
    Double:
    <div>
        <asp:TextBox ID="txtDouble" runat="server"></asp:TextBox>  
        <asp:CustomValidator ID="vldDouble" runat="server" ErrorMessage="Invalid double." 
            ControlToValidate="txtDouble" OnServerValidate="vldDouble_ServerValidate" 
            ValidationGroup="double" Display="Dynamic">
        </asp:CustomValidator>
        <asp:Label ID="lblDoubleSuccess" runat="server" Text="Valid double." Visible="false" CssClass="validation_success"></asp:Label>
    </div>
    <asp:Button ID="btnDouble" runat="server" Text="Validate" ValidationGroup="double"/>
    </fieldset>
    
    <fieldset>
    Integer:
    <div>
        <asp:TextBox ID="txtInteger" runat="server"></asp:TextBox>
        <asp:CustomValidator ID="vldInteger" runat="server" ErrorMessage="Invalid integer." 
            ControlToValidate="txtInteger" OnServerValidate="vldInteger_ServerValidate" 
            ValidationGroup="integer" Display="Dynamic">
        </asp:CustomValidator>
        <asp:Label ID="lblIntegerSuccess" runat="server" Text="Valid integer." Visible="false" CssClass="validation_success"></asp:Label>
    </div>
    <asp:Button ID="btnInteger" runat="server" Text="Validate" ValidationGroup="integer"/>
    </fieldset>
            
    <fieldset>
    Printable:
    <div>
        <asp:TextBox ID="txtPrintable" runat="server"></asp:TextBox>
        <asp:CustomValidator ID="vldPrintable" runat="server" ErrorMessage="Invalid printable." 
            ControlToValidate="txtPrintable" OnServerValidate="vldPrintable_ServerValidate" 
            ValidationGroup="printable" Display="Dynamic">
        </asp:CustomValidator>
        <asp:Label ID="lblPrintableSuccess" runat="server" Text="Valid printable." Visible="false" CssClass="validation_success"></asp:Label>
    </div>
    <asp:Button ID="btnPrintable" runat="server" Text="Validate" ValidationGroup="printable"/>
    </fieldset>
    
</asp:Content>
