export function Panel({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <section className={`ui-panel rounded-lg p-5 ${className}`}>
      {children}
    </section>
  );
}
