package demo.view;

import com.yubico.u2f.attestation.Attestation;
import com.yubico.u2f.data.DeviceRegistration;
import io.dropwizard.views.View;

public class FinishRegistrationView extends View {

    private Attestation attestation;
    private DeviceRegistration registration;

    public FinishRegistrationView(Attestation attestation, DeviceRegistration registration) {
        super("finishRegistration.ftl");
        this.attestation = attestation;
        this.registration = registration;
    }

    public Attestation getAttestation() {
        return attestation;
    }

    public DeviceRegistration getRegistration() {
        return registration;
    }

}
