package org.apereo.cas.deref;

import com.sun.jndi.ldap.Ber;
import com.sun.jndi.ldap.BerEncoder;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.ldaptive.control.AbstractControl;
import org.ldaptive.control.RequestControl;
import org.springframework.ldap.control.AbstractRequestControlDirContextProcessor;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.Control;
import java.util.HashMap;
import java.util.Map;

/**
 * Dereference control for openLdap servers to perform the dereference operation of an object.
 * See https://datatracker.ietf.org/doc/html/draft-masarati-ldap-deref-00
 *
 * @author  Anna Kavvada
 */

@Slf4j
public class DereferenceControl extends AbstractRequestControlDirContextProcessor implements RequestControl{

    private static final long serialVersionUID = -8256507599052732117L;

    public static final String OID = "1.3.6.1.4.1.4203.666.5.16";
    private final boolean critical;
    private HashMap<String,String> dereference;
    private byte[] berVal;

    public DereferenceControl(){
        this.critical = false;
    }

    @Override
    public Control createRequestControl() {
        val dereferenceRequestControl = new DereferenceRequestControl(dereference, critical);
        return dereferenceRequestControl.createRequestControl();
    }

    public DereferenceControl(HashMap<String, String> deref_val, boolean critical) throws NullPointerException{
        //super(OID, critical);
        this.critical = critical;
        this.dereference=deref_val;

        //this error, unless addressed, blows up during ber encoding.
        if( dereference == null )
        {
            throw new NullPointerException("DerefReqControl(): Null dereference attribute argument");
        }

        /*
         * Ber format: {{derefAttrName{attrName1,attrName2,...}}{derefAttrName2{attrNameX,attrNameY...}}...}
         */
        BerEncoder ber = new BerEncoder(1);
        try
        {
            ber.beginSeq(Ber.ASN_SEQUENCE | Ber.ASN_CONSTRUCTOR);
            for( Map.Entry<String,String> entry : dereference.entrySet() )
            {
                String curDerefAttrName = entry.getKey();
                String attrs_to_deref = entry.getValue();

                ber.beginSeq(Ber.ASN_SEQUENCE | Ber.ASN_CONSTRUCTOR);
                ber.encodeString(curDerefAttrName, Ber.ASN_SIMPLE_STRING , true); //encodeUTF8 = true
                ber.beginSeq(Ber.ASN_SEQUENCE | Ber.ASN_CONSTRUCTOR);

                String[] tmpAttrs = attrs_to_deref.split(",");
                for(int j=0;j<tmpAttrs.length;j++)
                {
                    ber.encodeString(tmpAttrs[j], Ber.ASN_SIMPLE_STRING, true); //encodeUTF8 = true
                }
                ber.endSeq();
                ber.endSeq();
            }
            ber.endSeq();
        }
        catch (Exception ex)
        {
            LOGGER.error("Ber encoding error",ex);
        }
        this.berVal=ber.getBuf();
    }


    @Override
    public int hashCode() {
        return 0;
    }

    @Override
    public byte[] encode() {
        return new byte[0];
    }

    @Override
    public boolean hasValue() {
        return false;
    }

    @Override
    public String getOID() {
        return null;
    }

    @Override
    public boolean getCriticality() {
        return false;
    }

    @Override
    public void postProcess(DirContext ctx) throws NamingException {

    }
}

