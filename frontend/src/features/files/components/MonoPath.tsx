import { rpDisplay, type RemotePath } from "../../../sftp-path";

export function MonoPath({ rp }: { rp: RemotePath }) {
  return <code className="fs-mono-path">{rpDisplay(rp)}</code>;
}
