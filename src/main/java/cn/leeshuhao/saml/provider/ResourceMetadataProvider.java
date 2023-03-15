package cn.leeshuhao.saml.provider;

import org.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.springframework.core.io.Resource;

import java.io.IOException;

/**
 * <p>获取IDP xml文件内容</p>
 *
 * @author MrLee
 */
public class ResourceMetadataProvider extends AbstractMetadataProvider {

    private final Resource resource;

    public ResourceMetadataProvider(Resource resource) {
        this.resource = resource;
    }

    @Override
    protected XMLObject doGetMetadata() throws MetadataProviderException {
        try {
            return super.unmarshallMetadata(resource.getInputStream());
        } catch (UnmarshallingException | IOException e) {
            throw new MetadataProviderException(e);
        }
    }
}
